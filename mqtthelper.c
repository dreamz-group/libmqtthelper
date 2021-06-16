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

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include "dbgprint.h" 
#include "mqtthelper.h"
#include "mqtthelper-config.h"
#include "select_cb.h"

#include <mosquitto.h>
#include <ctype.h>

typedef struct
{
    cb_helper_p user_function;
    char*       topic;
    void*       local_id;
    void*       user_data;
} helper_device_t;

typedef struct 
{
    struct mosquitto* mosq;
    int               last_fd;
    int               dev_max;
    helper_device_t devices[MQTT_HELPER_DEVICE_MAX];
} helper_handle_t;



static helper_handle_t mqtt_helper_handles[MQTT_HELPER_HANDLE_MAX];

static int dispatch_mqtt_message(helper_handle_t* handle, const char *topic, const void *msg, int msg_len);
static void mqtt_message_cb(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg);


static int _mqtt_force_publish_ex(helper_handle_t* handle)
{
    int rtn = MOSQ_ERR_SUCCESS;
    while( mosquitto_want_write(handle->mosq) )
    {
        rtn = mosquitto_loop_write(handle->mosq,10);
        if( rtn != MOSQ_ERR_SUCCESS ) 
        {
            dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "Connection lost\n");
            return rtn;
        }
    }
    return rtn;
}

int mqtt_force_publish()
{
    return _mqtt_force_publish_ex(&mqtt_helper_handles[0]);
}

int mqtt_force_publish_ex(mqtt_helper_handle_t handle)
{
    return _mqtt_force_publish_ex(&mqtt_helper_handles[handle]);
}

static int _mqtt_helper_loop_int(helper_handle_t* handle)
{
    int rtn = MOSQ_ERR_SUCCESS;
    
    while( mosquitto_want_write(handle->mosq) )
    {
        rtn = mosquitto_loop_write(handle->mosq,10);
        if( rtn != MOSQ_ERR_SUCCESS ) 
        {
            dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "Connection lost\n");
            return rtn;
        }
    }
    mosquitto_loop_misc(handle->mosq); 
    return rtn;
}

int mqtt_helper_loop()
{
    return _mqtt_helper_loop_int( &mqtt_helper_handles[0] );
}

int mqtt_helper_loop_ex(mqtt_helper_handle_t handle)
{
    return _mqtt_helper_loop_int( &mqtt_helper_handles[handle] );
}

char *get_input_val(char *dname, size_t len, const char *needle, const char *haystack)
{
    char *rp;
    char *ret = dname;

    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "DBGprint change request: (%s) -in-> (%s)\n", needle, haystack);

    rp = (char *)strstr(haystack, needle);

    if (!rp)
    {
        dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "DBGprint input error, ignore command (%s)..\n", haystack);
        return rp;
    }

    rp += strlen(needle);

    // Skip space and :
    for (; *rp == ' ' || *rp == ':' || *rp == '\0'; rp++)
    {
        dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_VERBOSE, "DBGprint -> (%c) (%s)..\n", *rp, rp);
    }
    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_VERBOSE, "DBGprint -> (%s)..\n", rp);

    // Is it a string? -> "
    if (*rp == '"')
    {
        // Jump one and copy value...
        for (rp++; *rp != '"' && *rp != '\0' && (size_t)(dname - ret) < len; rp++, dname++)
        {
            *dname = *rp;
        }
        *dname = '\0';
    }
    else if (isdigit(*rp))
    {
        // While alpha num...
        for (; isdigit(*rp) && (size_t)(dname - ret) < len; rp++, dname++)
        {
            *dname = *rp;
        }
        *dname = '\0';
    }
    else
    {
        dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "Error parsing input...\n");
        return NULL;
    }

    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_VERBOSE, "DBGprint DONE-> (%s)\n", ret);
    return ret;
}

int mqtt_dbgprint_handle_callback(void *local_id, const char *topic, void *msg, int msg_len, void *user_data)
{
    char dname[30];
    printgrp ret;

    get_input_val(dname, sizeof(dname), "\"grp\"", (const char *)msg);
    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_INFO, "grp (%s)\n", dname);

    // Check if Group excists
    ret = dbgmsg_name_to_grpid(dname); // Ex "DBG_GRP_DEVELOP"
    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_VERBOSE, "VALUE SET TO (%d)\n", ret);

    // Find level   -->  "level" : "name"
    get_input_val(dname, sizeof(dname), "\"level\"", (const char *)msg);
    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_INFO, "level (%s)\n", dname);

    // Set module to level
    dbgmsg_set(ret, (printlevel)atoi(dname));

    return 0;
}

int mqtt_dbgprint_init(const char *daemon_name)
{
    return mqtt_dbgprint_init_ex( 0, daemon_name);
}

int mqtt_dbgprint_init_ex(mqtt_helper_handle_t handle, const char *daemon_name)
{
    char buf[200] = "dbgprint"; 

    // Init Lib
    dbgmsg_init(daemon_name);

    // Setup callback on MQTT dbgprint messages...
    // Topic: dbgprint   => For all
    mqtt_helper_add_ex(handle, buf, &mqtt_dbgprint_handle_callback, NULL, NULL);

    // Topic: dbgprint/daemon_name => For this, use the same as for all..
    snprintf(buf, sizeof(buf), "dbgprint/%s", daemon_name);
    mqtt_helper_add_ex(handle, buf, &mqtt_dbgprint_handle_callback, NULL, NULL);

    return 0;
}

// --------------------------
// Find path and use wildchar
//
// returns: null if fails else pointer to....
//
// NOTE:
// If you like to find more then first match, update device_array to start after first hit...
// --------------------------
static helper_device_t *mqtt_topic_check(helper_handle_t *handle, const char *query, bool include_wildchar, int pos)
{
    const char *r, *q;
    helper_device_t *p;
    helper_device_t *start = &handle->devices[pos];

    for (p = start; (p - start) < handle->dev_max; p++)
    {
        if (p->topic == NULL)
        {
            continue;
        }

        // Check for exact match...
        if (!include_wildchar)
        {
            if (strcmp(query, p->topic) == 0)
            {
                return p;
            }
            continue;
        }

        // Wildchar search...
        for (r = p->topic, q = query; *r != 0 && *q != 0; q++, r++)
        {
            // if character match continue
            if (*r == *q)
            {
                continue;
            }

            // Check if we subscribed to wildchar
            if (*r == '#' || *r == '+')
            {
                if (*(r + 1) == '\0')
                {
                    return p;
                }

                if (*(r + 1) == '/')
                {
                    // Jump to next /
                    for (; *q != '/' && *q != '\0'; q++)
                        ;

                    if (*q == '/')
                    {
                        q--;
                    }
                    else if (*q == '\0')
                    {
                        // Fix for x/+/y/+/z  should not pass x/5
                        if (*r == '#')
                            return p;

                        continue;
                    }
                    continue;
                }
            }

            // check if character is wildchar
            if (*q == '#' || *q == '+')
            {
                if (*(q + 1) == '\0')
                    return p;

                // jump to next / if any then continue.
                for (; *r != '/' && *r != '\0'; r++)
                    ;

                if (*r == '/')
                {
                    r--;
                }
                else if (*r == '\0')
                {
                    return p;
                }

                continue;
            }

            // Else break, no match
            break;
        }

        if (*r == *q)
        {
            return p;
        }
    }

    return NULL;
}

static int _mqtt_helper_init(helper_handle_t* handle, const char* host, int port, const char* username, const char* password, const char* cert, const char* key, const char* capath, const char* cafile, int keepalive, const char* clientId )
{
    int ret;

    // Print welcome...
    dbgmsg(DBG_GRP_STARTUP, DBG_PRINT_INFO, "Started mqtt_helper (%s:%d %d) in %s\n", host, port, keepalive, __FILE__);

    // Prepare for fresh start    
    handle->last_fd = -1;
    handle->dev_max = 0;
    memset(handle->devices, 0, sizeof(helper_device_t) *MQTT_HELPER_DEVICE_MAX);
    static int first = 0;
    if( first == 0 )
    {
        dbgmsg(DBG_GRP_STARTUP, DBG_PRINT_INFO, "Loading Mosquitto library\n");
        mosquitto_lib_init();
        first = 1;
    }

    handle->mosq = mosquitto_new(clientId, true, NULL);
    if (!handle->mosq)
    {
        dbgmsg(DBG_GRP_STARTUP, DBG_PRINT_ERROR, "Can't init Mosquitto library\n");
        exit(-1);
    }

    // Set up username and password
    if( username != NULL && password != NULL )
    {
        mosquitto_username_pw_set(handle->mosq, username, password );
    }

    if( capath != NULL ) // This forces TLS with or with out client certs.
    {    
        ret = mosquitto_tls_set(handle->mosq, cafile, capath, cert, key, NULL);
        if( ret != MOSQ_ERR_SUCCESS )
        {
            dbgmsg(DBG_GRP_NETWORK, DBG_PRINT_ERROR, "Failed to setup mosquitto for secure connnection\n");
            return ret;
        }
#if DEBUG
        const char* unsecure = getenv("unsecure");
        if( unsecure != NULL && strcmp(unsecure, "true") == 0 )
        {
            dbgmsg(DBG_GRP_NETWORK, DBG_PRINT_WARNING, "Setting connection insecure!\n");
            mosquitto_tls_insecure_set(handle->mosq, true);
        }
#endif
    }

    mosquitto_message_callback_set(handle->mosq, mqtt_message_cb);

    // Establish a connection to the MQTT server. Do not use a keep-alive ping
    ret = mosquitto_connect(handle->mosq, host, port, keepalive);

    if (ret)
    {
        dbgmsg(DBG_GRP_NETWORK, DBG_PRINT_ERROR, "Can't connect to Mosquitto server\n");
        mosquitto_destroy(handle->mosq);
        exit(-1);
    }

    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_INFO, "MQTT socket created (%d)\n");

    return ret;
}

int mqtt_helper_init()
{
    return _mqtt_helper_init(&mqtt_helper_handles[0], MQTT_HOSTNAME, MQTT_PORT, MQTT_USERNAME, MQTT_PASSWORD, NULL, NULL, NULL, NULL, 0, NULL);
}

mqtt_helper_handle_t mqtt_helper_init_azure(const char* iot_hub_name, const char* deviceId, const char* SasToken, int keepalive )
{
    static const char* _capath = "/etc/ssl/certs/";
    
    char username[256];
    snprintf(username,sizeof(username), "%s.azure-devices.net/%s/api-version=2016-11-14", iot_hub_name, deviceId);
    
    char host[128];
    snprintf(host,sizeof(host),"%s.azure-devices.net", iot_hub_name);

    int i;
    for(i=0; i < MQTT_HELPER_HANDLE_MAX; ++i )
    {
        if ( mqtt_helper_handles[i].mosq == NULL )
        {
            if( _mqtt_helper_init(&mqtt_helper_handles[i], host, 8883, username, SasToken, NULL, NULL, _capath, NULL, keepalive, deviceId) != 0 )
            {
                break;
            }
            return i;
        }
    }
    return MQTT_HELPER_HANDLE_INVALID;
}

mqtt_helper_handle_t mqtt_helper_init_ex(const char* host, int port, const char* username, const char* password, int keepalive )
{
    int i;
    for(i=0; i < MQTT_HELPER_HANDLE_MAX; ++i )
    {
        if ( mqtt_helper_handles[i].mosq == NULL )
        {
            if( _mqtt_helper_init(&mqtt_helper_handles[i], host, port, username, password, NULL, NULL, NULL, NULL, keepalive, NULL) != 0 )
            {
                break;
            }
            return i;
        }
    }
    return MQTT_HELPER_HANDLE_INVALID;
}

mqtt_helper_handle_t mqtts_helper_init_cert_ex(const char* host, int port, const char* cert, const char* key, const char* capath, const char* cafile, int keepalive)
{
    int i = MQTT_HELPER_HANDLE_INVALID;
    for(i=0; i < MQTT_HELPER_HANDLE_MAX; ++i )
    {
        if ( mqtt_helper_handles[i].mosq == NULL )
        {
            break;
        }
    }

    if( i >= MQTT_HELPER_HANDLE_MAX )
    {
        return MQTT_HELPER_HANDLE_INVALID;
    }

    // Set up username and password
    const char* _capath = MQTT_DEFAULT_CA_PATH;
    const char* _cert   = MQTT_DEFAULT_CERT_FILE;
    const char* _key    = MQTT_DEFAULT_KEY_FILE;
    if( cert == NULL )
    {
        cert = _cert;
    }
    
    if( key == NULL )
    {
        key = _key;
    }

    if( capath == NULL )
    {
        capath = _capath;
    }           
    return _mqtt_helper_init(&mqtt_helper_handles[i], host, port, NULL,     NULL,     cert, key,  capath, cafile, keepalive, NULL ) == 0 ? i : MQTT_HELPER_HANDLE_INVALID;
}

// =========== MQTT callbacks ============
static void mqtt_message_cb(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    int i;

    for( i=0; i < MQTT_HELPER_HANDLE_MAX; ++i )
    {
        if( mqtt_helper_handles[i].mosq == mosq )
        {
            dispatch_mqtt_message( &mqtt_helper_handles[i], msg->topic, msg->payload, msg->payloadlen);
            return;
        }
    }
    dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "Handle is not active!?, operation failed.\n");
}

static int _mqtt_helper_disconnect_int(helper_handle_t *handle)
{
    int ret;
    dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "Disconnect.\n");
    
    ret = mosquitto_disconnect( handle->mosq );
    
    return ret; //MOSQ_ERR_SUCCESS; || MOSQ_ERR_NO_CONN	|| MOSQ_ERR_INVAL
}

int mqtt_helper_disconnect()
{
    return _mqtt_helper_disconnect_int(&mqtt_helper_handles[0]);
}

int mqtt_helper_disconnect_ex(mqtt_helper_handle_t handle)
{
    return _mqtt_helper_disconnect_int(&mqtt_helper_handles[handle]);
}

static int _mqtt_helper_reconnect_int(helper_handle_t *handle)
{
    helper_device_t *p;
    int rtn = mosquitto_reconnect( handle->mosq );
    if( rtn != MOSQ_ERR_SUCCESS )
    {
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "Reconnection failed with status: (%d)...\n", rtn);
        return rtn;
    }

    // Specify the function to call when a new message is received
    mosquitto_message_callback_set(handle->mosq, mqtt_message_cb);

    for (p = handle->devices; (p - handle->devices) < handle->dev_max; p++)
    {
        if (p->topic == NULL)
        {
            continue;
        }
        int ret = mosquitto_subscribe(handle->mosq, NULL, p->topic, 0);

        if (ret)
        {
            dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "Can't subscribe to Mosquitto server [%s] (%d)...\n", p->topic, ret);
            dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "ERR: [%s]...\n", ret == MOSQ_ERR_SUCCESS ? "MOSQ_ERR_SUCCESS" : ret == MOSQ_ERR_INVAL ? "MOSQ_ERR_INVAL" : ret == MOSQ_ERR_NOMEM ? "MOSQ_ERR_NOMEM" : ret == MOSQ_ERR_NO_CONN ? "MOSQ_ERR_NO_CONN" : "Unknown...");
            exit(-1);
        }
    }
    return MOSQ_ERR_SUCCESS;
}

int mqtt_helper_reconnect()
{
    return _mqtt_helper_reconnect_int(&mqtt_helper_handles[0]);
}

int mqtt_helper_reconnect_ex(mqtt_helper_handle_t handle)
{
    return _mqtt_helper_reconnect_int(&mqtt_helper_handles[handle]);
}


void mqtt_helper_cleanup_ex(mqtt_helper_handle_t handle)
{
    dbgmsg(DBG_GRP_STARTUP, DBG_PRINT_INFO, "mqtt cleanup %s\n" __FILE__);
    mosquitto_destroy(mqtt_helper_handles[handle].mosq);
    mqtt_helper_handles[handle].mosq = NULL;
    mosquitto_lib_cleanup();
    if( mqtt_helper_handles[handle].last_fd != -1 )
    {
        cb_del(mqtt_helper_handles[handle].last_fd);
        mqtt_helper_handles[handle].last_fd = -1;
    }
    return;
}

void mqtt_helper_cleanup()
{
    mqtt_helper_cleanup_ex(0);
}

int mqtt_helper_add(const char *topic, cb_helper_p user_function, void *local_id, void *user_data)
{
    return mqtt_helper_add_ex(0, topic, user_function, local_id, user_data);
}

int mqtt_helper_add_ex(mqtt_helper_handle_t handle, const char *topic, cb_helper_p user_function, void *local_id, void *user_data)
{
    int ret;
    helper_device_t *p;

    // Make sure topic does not allready is taken..
    if (mqtt_topic_check(&mqtt_helper_handles[handle], topic, false, 0) != NULL)
    {
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_WARNING, "Topic %s in use, operation failed.\n", topic);
        return -2;
    }

    // find empty slot.
    helper_device_t* start = mqtt_helper_handles[handle].devices;    
    for (p = start; (p - start) < MQTT_HELPER_DEVICE_MAX && p->topic != NULL; p++)
    {
        ;
    }
    int pos = p - start;
    // check if no free slots found...
    if ( pos >= MQTT_HELPER_DEVICE_MAX )
    {
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_WARNING, "No free slots, ignoring command.\n");
        return -1;
    }

    // add callback
    ret = mosquitto_subscribe(mqtt_helper_handles[handle].mosq, NULL, topic, 0);

    if (ret)
    {
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "Can't subscribe to Mosquitto server [%s] (%d)...\n", topic, ret);
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "ERR: [%s]...\n", ret == MOSQ_ERR_SUCCESS ? "MOSQ_ERR_SUCCESS" : ret == MOSQ_ERR_INVAL ? "MOSQ_ERR_INVAL" : ret == MOSQ_ERR_NOMEM ? "MOSQ_ERR_NOMEM" : ret == MOSQ_ERR_NO_CONN ? "MOSQ_ERR_NO_CONN" : "Unknown...");
        exit(-1);
    }

    // copy data...
    if( mqtt_helper_handles[handle].dev_max <= pos )
    {
        mqtt_helper_handles[handle].dev_max = pos + 1;
    }

    p->topic         = strdup(topic);
    p->user_function = user_function;
    p->local_id      = local_id;
    p->user_data     = user_data;

    return 0;
}

int mqtt_helper_del(const char *topic)
{
    return mqtt_helper_del_ex(0, topic);
}

int mqtt_helper_del_ex(mqtt_helper_handle_t handle, const char *topic)
{
    helper_device_t *p;

    // find slot/s
    if ((p = mqtt_topic_check(&mqtt_helper_handles[handle], topic, false, 0)) == NULL)
    {
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_WARNING, "Cant delete: topic not in use.\n");
        return -3;
    }

    // free name string (strdup uses malloc...)
    free(p->topic);
    memset(p, 0, sizeof(helper_device_t));

    return 0;
}

int mqtt_helper_get_fd_ex(mqtt_helper_handle_t handle)
{
    return mosquitto_socket(mqtt_helper_handles[handle].mosq);
}

int mqtt_helper_get_fd()
{
    return mosquitto_socket(mqtt_helper_handles[0].mosq);
}

static int mqtt_helper_get_msg_int(helper_handle_t* handle)
{
    return mosquitto_loop(handle->mosq, 0, 1);
}

int mqtt_helper_get_msg_ex(mqtt_helper_handle_t handle)
{
    return mqtt_helper_get_msg_int(&mqtt_helper_handles[handle]);
}

int mqtt_helper_get_msg()
{
    return mqtt_helper_get_msg_int(&mqtt_helper_handles[0]);
}

int mqtt_helper_publish(const char *topic, const void *payload, size_t payload_len)
{
    return mqtt_helper_publish_ex(0, topic, payload, payload_len);
}

int mqtt_helper_publish_ex(mqtt_helper_handle_t handle, const char *topic, const void *payload, size_t payload_len)
{
    int ret;

    dbgmsg(DBG_GRP_MQTT, DBG_PRINT_VERBOSE, "MQTT(%d) Sending to topic:(%s)\n", handle, topic);

    // Send message
    ret = mosquitto_publish(mqtt_helper_handles[handle].mosq, NULL, topic, payload_len, payload, 0, false);
    if (ret)
    {
        dbgmsg(DBG_GRP_MQTT, DBG_PRINT_ERROR, "Can't publish to Mosquitto server\n");
        exit(-1);
    }
    return 0;
}

// dispatch mqtt messages
static int dispatch_mqtt_message(helper_handle_t* handle, const char *topic, const void *msg, int msg_len) //, void *payload)
{
    int i=0;
    helper_device_t *p;

    // Loop through array and  Just launch all matching callbacks...
    for (p = handle->devices; (p = mqtt_topic_check(handle, topic, true, p - handle->devices)) != NULL; p++)
    {
        // Launch function..
        p->user_function(p->local_id, topic, (void*)msg, msg_len, p->user_data);
        i++;
    }
    return i;
}



/// CONNECTION STUFF
static void mqtt_reconnect(helper_handle_t* p);

static int mqtt_fd_cb(int fd, void *user_data)
{
    helper_handle_t* p = (helper_handle_t*)user_data;
    if( mqtt_helper_get_msg_int(p) != 0 )
    {
        mqtt_reconnect(p);
    }
    return 0;
}

static void mqtt_reconnect(helper_handle_t* p )
{
    // If we have a fd we need to remove it from select cb else we will have dead fd's in the list.
    if( p->last_fd != -1 )
    {
        cb_del(p->last_fd);
        p->last_fd = -1;
    }

    dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "reconnect -> Attempting to reconnect\n");
    if( _mqtt_helper_reconnect_int(p) != 0 )
    {
        dbgmsg(DBG_GRP_DEVELOP, DBG_PRINT_WARNING, "reconnect -> Faild to mosquitto broker\n");
        return;
    }
    p->last_fd = mosquitto_socket(p->mosq);
    cb_add(p->last_fd, &mqtt_fd_cb, p);
}

static int mqtt_connection_cb(time_t epoc_wake_uptime, void *user_data)
{
    helper_handle_t* p = (helper_handle_t*)user_data;

    if( p->last_fd == -1 || _mqtt_helper_loop_int(p) != 0 )
    {
        mqtt_reconnect(p);
    }
    return 0;
}

void mqtt_helper_connection_monitor()
{
    mqtt_helper_connection_monitor_ex(0);
}

void mqtt_helper_connection_monitor_ex(mqtt_helper_handle_t handle)
{
    helper_handle_t* p = &mqtt_helper_handles[handle];
    p->last_fd = mosquitto_socket(p->mosq);
    if( p->last_fd != -1 )
    {
        cb_add( p->last_fd, &mqtt_fd_cb, p);
    }
    cb_to_repeat_add(5, &mqtt_connection_cb, p);
}

int mqtt_helper_trigger_ex(mqtt_helper_handle_t handle, const char* topic, const void *payload, size_t payload_len)
{
    helper_handle_t* p = &mqtt_helper_handles[handle];
    return dispatch_mqtt_message( p, topic, payload, payload_len);
}

int mqtt_helper_trigger(const char* topic, const void *payload, size_t payload_len)
{
    return mqtt_helper_trigger_ex(0, topic, payload, payload_len);
}
