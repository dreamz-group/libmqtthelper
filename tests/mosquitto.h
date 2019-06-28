/*
MIT License

Copyright (c) 2019 dreamz-group

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

enum mosq_err_t
{
    MOSQ_ERR_CONN_PENDING = -1,
    MOSQ_ERR_SUCCESS = 0,
    MOSQ_ERR_NOMEM = 1,
    MOSQ_ERR_PROTOCOL = 2,
    MOSQ_ERR_INVAL = 3,
    MOSQ_ERR_NO_CONN = 4,
    MOSQ_ERR_CONN_REFUSED = 5,
    MOSQ_ERR_NOT_FOUND = 6,
    MOSQ_ERR_CONN_LOST = 7,
    MOSQ_ERR_TLS = 8,
    MOSQ_ERR_PAYLOAD_SIZE = 9,
    MOSQ_ERR_NOT_SUPPORTED = 10,
    MOSQ_ERR_AUTH = 11,
    MOSQ_ERR_ACL_DENIED = 12,
    MOSQ_ERR_UNKNOWN = 13,
    MOSQ_ERR_ERRNO = 14,
    MOSQ_ERR_EAI = 15,
    MOSQ_ERR_PROXY = 16,
    MOSQ_ERR_PLUGIN_DEFER = 17,
    MOSQ_ERR_MALFORMED_UTF8 = 18,
    MOSQ_ERR_KEEPALIVE = 19,
    MOSQ_ERR_LOOKUP = 20,
};

struct mosquitto_message
{
    int mid;
    char *topic;
    void *payload;
    int payloadlen;
    int qos;
    bool retain;
};

struct mosquitto
{
};

static struct mosquitto _mosq_;

int mosquitto_subscribe(struct mosquitto *mosq, int *mid, const char *sub, int qos)
{
    return 0;
}

int mosquitto_loop_write(struct mosquitto *mosq, int max_packets)
{
    return 0;
}

int mosquitto_loop_misc(struct mosquitto *mosq)
{
    return 0;
}

bool mosquitto_want_write(struct mosquitto *mosq)
{
    return false;
}

void mosquitto_lib_init()
{
}

struct mosquitto *mosquitto_new(const char *id, bool clean_session, void *obj)
{
    return &_mosq_;
}

int mosquitto_username_pw_set(struct mosquitto *mosq, const char *username, const char *password)
{
    return 0;
}

int mosquitto_tls_set(struct mosquitto *mosq,
                      const char *cafile, const char *capath,
                      const char *certfile, const char *keyfile,
                      int (*pw_callback)(char *buf, int size, int rwflag, void *userdata))
{
    return 0;
}

void mosquitto_message_callback_set(struct mosquitto *mosq, void (*on_message)(struct mosquitto *, void *, const struct mosquitto_message *))
{
    return;
}

int mosquitto_tls_insecure_set(struct mosquitto *mosq, bool value)
{
    return 0;
}

int mosquitto_socket(struct mosquitto *mosq)
{
    return 0;
}

int mosquitto_connect(struct mosquitto *mosq, const char *host, int port, int keepalive)
{
    return 0;
}

void mosquitto_destroy(struct mosquitto *mosq)
{
}

int mosquitto_reconnect(struct mosquitto *mosq)
{
    return 0;
}

int mosquitto_disconnect(struct mosquitto *mosq)
{
    return 0;
}

int mosquitto_lib_cleanup(void)
{
    return 0;
}

int mosquitto_loop(struct mosquitto *mosq, int timeout, int max_packets)
{
    return 0;
}

int mosquitto_publish(struct mosquitto *mosq, int *mid, const char *topic, int payloadlen, const void *payload, int qos, bool retain)
{
    return 0;
}