#include <module.h>
#include <dryos.h>
#include <property.h>
#include <bmp.h>

#include "string.h"
#include "fio-ml.h"
#include "config.h"
#include "ml_socket.h"

#include "yolo.h"

static const uint32_t SERVER_RESP_MAX = 256;

// allow compiling module if uart_printf stub isn't defined
static int dummy_uart_printf(const char *fmt, ...)
{
    return 0;
}
extern WEAK_FUNC(dummy_uart_printf) int uart_printf(const char *fmt, ...);

// This assumes a digic 678X cam.
// Currently this module won't init unless you're a 200D,
// so that's fine.
static void get_screen(uint8_t *yuv_buf, uint32_t buf_size, uint32_t *width, uint32_t *height)
{
    uint8_t *lvram = NULL;
    struct vram_info *vram_info = get_yuv422_vram();

    if (vram_info != NULL)
        lvram = vram_info->vram;

// skipping this for now, it's in consts.h, not sure on a nice way
// to pull this in.  We can just send back uninit data I suppose
//    if (YUV422_LV_BUFFER_DISPLAY_ADDR == 0x01000000) // indicates uninit buffer
//        lvram = NULL;

    if (lvram == NULL)
        return;

    uint32_t vram_size = vram_lv.height * vram_lv.pitch; // SJE FIXME does screenshot have this wrong?
                                                         // It allocates width * pitch, which seems incorrect
                                                         // (but always bigger than needed, so won't crash)
    *width = vram_lv.width;
    *height = vram_lv.height;
    if (vram_size <= buf_size * 2) // buf is expected to be half size, we discard chroma bytes
    {
        // let's assume vram width is always a multiple of 8
        uint32_t *src = (uint32_t *)lvram;
        uint32_t *dst = (uint32_t *)yuv_buf;

        uint32_t s1, s2, d;
        while (src < (uint32_t *)(lvram + vram_size))
        {
            // keep the 4 luminance bytes for every 8 bytes in orig yuv buffer
            s1 = *src;
            s2 = *(src + 1);
            d =  (s1 & 0x0000ff00) >> 8;
            d |= (s1 & 0xff000000) >> 16;
            d |= (s2 & 0x0000ff00) << 8;
            d |= (s2 & 0xff000000);
            src += 2;
            *dst = d;
            dst++;
        }
    }
    else
    {
        uart_printf("vram too big: 0x%x\n", vram_size);
        uart_printf("height, width, pitch: %d, %d, %d\n",
                    vram_lv.height, vram_lv.width, vram_lv.pitch);
    }
}

// parse the detection data from yolo_server.py and draw
// appropriate rectangles
static void display_detections(uint8_t *server_data)
{
    int type, count;
    int colours[] = {COLOR_YELLOW, COLOR_RED, COLOR_CYAN, COLOR_GREEN1, COLOR_ORANGE};
    int colour_index = 0;

    type = server_data[0];
    if (type == 1)
    {
        count = server_data[1];
        if (count < 0)
            return;

        // clear the middle of the screen, preserve the borders where ML draws info stuff
        bmp_fill(0x0, 30, 32, 660, 414);
//        bmp_draw_rect(COLOR_BLACK, 30, 32, 660, 414);

        uint8_t *payload = server_data + 6;
        uint16_t x, y, w, h;
        for (int n = count; n > 0; n--)
        {
            char *name = (char *)payload;
            int name_len = strlen(name);
            payload += (name_len + 1);

            x = *(uint16_t *)(payload + 0);
            y = *(uint16_t *)(payload + 2);
            w = *(uint16_t *)(payload + 4);
            h = *(uint16_t *)(payload + 6);

            uart_printf("detection: %s", name);
            uart_printf("\n\t %d, %d, %d, %d\n", x, y, w, h);

            // only draw if the co-ords are sensibly inside the screen
            // (drawing outside is buffer overflow!)
            if (y > 30 && x > 30 && y < 450 && x < 700
                && (x + w < 700) && (y + h < 450))
            {
                bmp_printf(FONT_MED, x, y - 30, name);
                bmp_draw_rect(COLOR_BLACK, x - 4, y - 4, w + 8, h + 8);
                bmp_draw_rect(colours[colour_index], x - 3, y - 3, w + 6, h + 6);
                bmp_draw_rect(colours[colour_index], x - 2, y - 2, w + 4, h + 4);
                bmp_draw_rect(colours[colour_index], x - 1, y - 1, w + 2, h + 2);
                bmp_draw_rect(COLOR_BLACK, x, y, w, h);
                colour_index++;
                colour_index = colour_index % COUNT(colours);
            }

            payload += 8;
        }
    }
    return;
}

// Get detection results from server.  See yolo_server.py.
static void get_detections(int socket, uint8_t *server_data)
{
    uint32_t recv_size;
    recv_size = socket_recv(socket, server_data, SERVER_RESP_MAX - 1, 0);

    if (recv_size < 6) // minimum size given the data format
    {
        uart_printf("err, socket_recv: %d\n", recv_size);
        server_data[0] = 0; // prevents parsing of bad data
        return;
    }
    uint32_t data_size = *(uint32_t *)(server_data + 2);
    if (data_size + 6 != recv_size)
    {
        uart_printf("err, data_size / recv_size mismatch: %d, %d\n",
                    data_size, recv_size);
        server_data[0] = 0; // prevents parsing of bad data
        return;
    }
//    uart_printf("socket_recv: %d\n", recv_size);
}

static void yolo_task(struct sockaddr_in *sockaddr)
{
    int socket = socket_create(1, 1, 0); // SJE FIXME make these named constants 
    if (socket < 0)
    {
        uart_printf("err, socket: %d\n", socket);
        return;
    }

    int retries = 0;
    int res = socket_connect(socket, sockaddr, sizeof(*sockaddr));
    while (retries < 3)
    {
        if (res < 0)
        {
            uart_printf("err, connect res: %d\n", res);
        }
        else
        {
            uart_printf("connect success\n");
            break;
        }
        msleep(900);
        retries++;
    }
    if (res < 0)
        return;

    // LV is YUV encoded, 2 bytes per pixel.  YOLO works fine on b&w,
    // so we can halve required bandwidth by only sending luminance channel.
    // Get space for this, plus a small amount for our Type, Length prefix.
    uint32_t total_size = (736 * 480) + 5;
    uint32_t data_size = total_size - 5;
    uint8_t *yuv_buf = malloc(total_size);
    if (yuv_buf == NULL)
        return;

    uint32_t height, width;
    uint8_t server_data[SERVER_RESP_MAX];
    memset(server_data, '\0', SERVER_RESP_MAX);
    TASK_LOOP
    {
        msleep(20); // this limits frame rate sent,
                    // but I find this is dominated by the slow network speed

        width = 0;
        height = 0;
        get_screen(yuv_buf + 5, data_size, &width, &height);

        if (width > 0)
        {
            uint32_t yuv_size = width * height;
            if (yuv_size > data_size)
            {
                uart_printf("yuv_sz > data_sz: %d, %d\n", yuv_size, data_size);
                yuv_size = data_size; // shouldn't happen, send truncated image if it does
            }
            *yuv_buf = 1; // A type field, should I want to extend this.  1 indicates
                          // the data is YUV.
            *((uint32_t *)(yuv_buf + 1)) = yuv_size; // size of following data
            socket_send(socket, yuv_buf, yuv_size + 5, 0);
            msleep(20);

            server_data[0] = 0;
            get_detections(socket, server_data);
            if (server_data[0] == 1)
                display_detections(server_data);
        }
    }

    socket_close_caller(socket_convertfd(socket));
}


// We expect to find ML/SETTINGS/WIFI.CFG.
// Config members are overwritten by the file contents
// and should therefore be null or uninit.
static int get_config(struct network_config *config)
{
    char filename[FIO_MAX_PATH_LENGTH];

    memset(config, '\0', sizeof(struct network_config));

    uint32_t config_buf_size = 1024;
    char *config_buf = malloc(config_buf_size); // expected max is < 256
    if (config_buf == NULL)
        return -1;
    memset(config_buf, '\0', config_buf_size);

    snprintf(filename, FIO_MAX_PATH_LENGTH, "%sWIFI.CFG", get_config_dir());
    FILE *f = FIO_OpenFile(filename, O_RDONLY | O_SYNC);

    if (f)
    {
        if (!FIO_ReadFile(f, config_buf, config_buf_size))
        {
            uart_printf("Couldn't read WIFI.CFG: %s\n", filename);
            free(config_buf);
            FIO_CloseFile(f);
            return -1;
        }
        FIO_CloseFile(f);
    }
    else
    {
        uart_printf("Couldn't open WIFI.CFG\n");
        free(config_buf);
        return -1;
    }

    // Parse file for network_config elements, copy into config.
    //
    // Each line must be null-terminated.
    // First line is SSID, second is passphrase,
    // Third is client IP that cam requests.  This is a decimal string.
    // Fourth is server IP.  This is as a decimal string.
    // Fifth is gateway IP.  A decimal string.
    // Sixth is server port, as a string.
    //
    // some_wifi_name
    // hunter22
    // 1711384768   // 192.168.1.102
    // 2399250624   // 192.168.1.143
    // 1040296128   // 192.168.1.62
    // 3451
    strncpy(config->SSID, config_buf, sizeof(config->SSID));
    config->SSID[sizeof(config->SSID) - 1] = '\0';
    int i = 0;
    int null_max = sizeof(config->SSID);
    while (i < null_max && config_buf[i] != '\0')
        i++;
    if (config_buf[i] != '\0')
        goto ret_err;
    i++;

    strncpy(config->passphrase, config_buf + i, sizeof(config->passphrase));
    config->passphrase[sizeof(config->passphrase) - 1] = '\0';
    null_max += sizeof(config->passphrase);
    while (i < null_max && config_buf[i] != '\0')
        i++;
    if (config_buf[i] != '\0')
        goto ret_err;
    i++;

    config->client_IP = atoi(config_buf + i);
    null_max += 10; // length of INT_MAX as a string
    while (i < null_max && config_buf[i] != '\0')
        i++;
    if (config_buf[i] != '\0')
        goto ret_err;
    i++;

    config->server_IP = atoi(config_buf + i);
    null_max += 10; // length of INT_MAX as a string
    while (i < null_max && config_buf[i] != '\0')
        i++;
    if (config_buf[i] != '\0')
        goto ret_err;
    i++;

    config->gateway_IP = atoi(config_buf + i);
    null_max += 10; // length of INT_MAX as a string
    while (i < null_max && config_buf[i] != '\0')
        i++;
    if (config_buf[i] != '\0')
        goto ret_err;
    i++;

    int port = atoi(config_buf + i);
    if (port > USHRT_MAX)
        goto ret_err;
    config->server_port = port;

    free(config_buf);
    return 0;
ret_err:
    free(config_buf);
    return -1;
}

// We require a working network connection,
// YOLO processing happens external to the camera.
unsigned int yolo_init()
{
    uart_printf(" ==== yolo: init start\n");
    msleep(2000); // wait for the Lime core to init?  Maybe not required

    // we hard-code some stuff for 200D, stop all other cams
    // proceeding:
    if (!is_camera("200D", "1.0.1"))
        return -1;
    
    static struct network_config config = {0};
    if (get_config(&config) < 0)
        return -1;

/*
    uart_printf("%s\n", config.SSID);
    uart_printf("%s\n", config.passphrase);
    uart_printf("%s\n", config.client_IP);
    uart_printf("0x%x\n", config.server_IP);
    uart_printf("%d\n", config.server_port);
*/

    static struct sockaddr_in sockaddr; // we pass this to yolo_task, static so it remains valid
    sockaddr.sin_family = SOCK_FAMILY_IPv4;
    // The bit mangling is htons(), which we don't have as a convenient function.
    // Should probably add a real htons() somewhere.
    sockaddr.sin_port = (config.server_port >> 8) | ((config.server_port & 0xff) << 8);
    sockaddr.sin_addr = config.server_IP;
    memset(sockaddr.sin_zero, '\0', sizeof(sockaddr.sin_zero));

    // prep the settings for wifi connection
    struct wlan_settings *wifi_settings = malloc(sizeof(*wifi_settings));
    if (wifi_settings == NULL)
        return -1;
    memset(wifi_settings, 0, sizeof(*wifi_settings));

    wifi_settings->unk_01 = 0;
    wifi_settings->mode = WLAN_MODE_INFRA;
    wifi_settings->mode_something = 2;
    strcpy(wifi_settings->SSID, config.SSID);
    wifi_settings->channel = 0; // 0 == auto?  It works, anyway.
    wifi_settings->auth_mode = WLAN_AUTH_MODE_WPA2PSK;
    wifi_settings->cipher_mode = WLAN_CIPHER_MODE_AES;
    wifi_settings->unk_02 = 0;
    wifi_settings->unk_03 = 6; // set to 6 when using INFRA or BOTH
    strcpy(wifi_settings->key, config.passphrase);

    // wake Lime core, this handles wifi
    call("NwLimeInit");
    call("NwLimeOn");

    // wake and config wlan
    call("wlanpoweron");
    call("wlanup");
    call("wlanchk");
//    call("wlanipset", config.client_IP); // Some values are not respected, on my network.  It seems I have to pick
                                         // a "static" IP that is in the valid range for dhcp IPs on my router.
                                         // Probably there is a way to configure this.
                                         //
                                         // Might be because we're setting IP before we connect to AP?


    int res = wlan_connect(wifi_settings);
    free(wifi_settings); // wlan_connect copies this to some global then never uses it again
    if (res != 0)
    {
        // 1 might be all errors, seen for bad pass and bad SSID
        uart_printf(" ==== error from wlan_connect: %d\n", res);
        return -1;
    }

    // set our IP and gateway
    nif_setup(0);
    res = set_IP_address(0, config.client_IP, 0x00ffffff, config.gateway_IP);
    if (res != 0)
    {
        uart_printf(" ==== error from set_IP_address: %d\n", res);
        uart_printf("ip, gw: 0x%x, 0x%x\n", config.client_IP, config.gateway_IP);
    }

    // some function pointer that changes after Lime core
    // is init, says Turtius.  But why do this loop after wlanconnect?
    //
    // The default is a ret void func.
    // This is replaced with a pointer to LimeDebugMsg() / e07347cc.
    // I imagine there's a cleaner way to detect init, but this works.
    //
    // 1d90c is part of networking related struct, see e0736290 and others.
    // Might not be the start of the struct.
    while (MEM(0x1d90c) == 0xe073631f)
    {
        msleep(100);
    }
    uart_printf(" ==== lime pointer changed to: 0x%x\n", MEM(0x1d90c));

    task_create("yolo", 0x1d, 0x1000, yolo_task, &sockaddr);

    return 0;
}

unsigned int yolo_deinit()
{
    return 0;
}

MODULE_INFO_START()
    MODULE_INIT(yolo_init)
    MODULE_DEINIT(yolo_deinit)
MODULE_INFO_END()

// might want callbacks for pushing screen content?
/*
MODULE_CBRS_START()
    MODULE_CBR(CBR_SHOOT_TASK, shoot_task_cbr, 0)
    MODULE_CBR(CBR_SECONDS_CLOCK, second_timer, 0)
MODULE_CBRS_END()

MODULE_PARAMS_START()
    MODULE_PARAM(test_parameter, "uint32_t", "Some test parameter")
MODULE_PARAMS_END()
*/

