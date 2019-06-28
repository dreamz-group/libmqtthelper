
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

#ifndef __MQTTHELPER_H__
#define __MQTTHELPER_H__
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef int (*cb_helper_p)(void *local_id, const char *topic, void *msg, int msg_len, void *user_data);

typedef long mqtt_helper_handle_t;
#define MQTT_HELPER_HANDLE_INVALID -1

// Adds a handler for a specific topic 
// @parma topic         - is the mqtt topic to subscribe too.
// @param user_function - is the callback to be called when a message arives on this topic.
// @param local_id      - user defined data identifying the call, not used internaly.
// @param user_data     - user data passed the to the callback, not used internaly.
// @return 0 on success.
int  mqtt_helper_add(const char *topic, cb_helper_p user_function, void *local_id, void *user_data);
int  mqtt_helper_add_ex(mqtt_helper_handle_t handle, const char *topic, cb_helper_p user_function, void *local_id, void *user_data);

// Init function, using default settings and use single instance version.
// returns 0 on success.
int  mqtt_helper_init();                 

// Init function
// @param host - is the hostname to connect too, default is localhost.
// @param port - is the port to connect too, default is 1883
// @param username - is the username to use for login, pass NULL if not used.
// @param password - password that matches username.
// @return handle on success, else MQTT_HELPER_HANDLE_INVALID.
mqtt_helper_handle_t mqtt_helper_init_ex(const char* host, int port, const char* username, const char* password, int keepalive );

// Init function
// @param host - is the hostname to connect too, default is localhost.
// @param port - is the port to connect too, default is 1883
// @param cert - client cert to be used or null (default /usr/local/etc/client.pem)
// @param key  - client cert key file of null (default /usr/local/etc/client.key)
// @param capath - ca path to be used or null (default /etc/ssl/certs)
// @return handle on success, else MQTT_HELPER_HANDLE_INVALID.
mqtt_helper_handle_t mqtts_helper_init_cert_ex(const char* host, int port, const char* cert, const char* key, const char* capath, int keepalive);

// Init function
// @param iot_hub_name - is the name of the iot_hub (with out the .azure-devices.net).
// @param deviceId     - is the deviceId used for this connection.
// @param SasToken     - This is the SasToken generated from GenerateSasToken.
// @return handle on success, else MQTT_HELPER_HANDLE_INVALID.
mqtt_helper_handle_t mqtt_helper_init_azure(const char* iot_hub_name, const char* deviceId, const char* SasToken, int keepalive );

// Reconnect a handler that have bin disconnected.
// @return 0 on success.
int mqtt_helper_reconnect();
int mqtt_helper_reconnect_ex(mqtt_helper_handle_t handle);

// Disconnect a handler that have been connected.
// @return 0 on success.
int mqtt_helper_disconnect();
int mqtt_helper_disconnect_ex(mqtt_helper_handle_t handle);

// Delete a handler for a specific topic
// returns 0 on success.
int  mqtt_helper_del(const char *topic); 
int  mqtt_helper_del_ex(mqtt_helper_handle_t handle, const char *topic); 

int  mqtt_helper_get_fd();                                  //!< Get fd used for select call
int  mqtt_helper_get_fd_ex(mqtt_helper_handle_t handle);    //!< Get fd used for select call

// Get read messages from the default handle if fd was triggerd.
// @return 0 on success, else the connection is most likly dear.
int mqtt_helper_get_msg();

// Get read messages from the handle if fd was triggerd.
// @param handle handle returnd from connect.
// @return 0 on success, else the connection is most likly dear.
int mqtt_helper_get_msg_ex(mqtt_helper_handle_t handle);

// Send a message on a specific topic
// returns 0 on success.
int  mqtt_helper_publish(const char *topic, const void *payload, size_t payload_len);
int  mqtt_helper_publish_ex(mqtt_helper_handle_t handle, const char *topic, const void *payload, size_t payload_len);

void mqtt_helper_cleanup();
void mqtt_helper_cleanup_ex(mqtt_helper_handle_t handle);

int  mqtt_dbgprint_init(const char *daemon_name);
int  mqtt_dbgprint_init_ex(mqtt_helper_handle_t handle, const char *daemon_name);

// mqtt helper loop, needs to be called on a regular bases to send qued items and/or handle internal states.
int mqtt_helper_loop();
int mqtt_helper_loop_ex(mqtt_helper_handle_t handle);

// starts mqtt connection monitor loop that handles reconnect and readding the callbacks.
void mqtt_helper_connection_monitor();
void mqtt_helper_connection_monitor_ex(mqtt_helper_handle_t handle);

// This function pushes a message out directly from the callback, requires a patch in mqtt to work.
int mqtt_force_publish();
int mqtt_force_publish_ex(mqtt_helper_handle_t handle);

// This triggers a topic callback with a certin payload.
int mqtt_helper_trigger(const char* topic, const void *payload, size_t payload_len);
int mqtt_helper_trigger_ex(mqtt_helper_handle_t handle, const char* topic, const void *payload, size_t payload_len);

#ifdef __cplusplus
} //extern "C"
#endif
#endif
