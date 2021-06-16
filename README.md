# libmqtthelper
This library is used to simplefy implementation of mqtt clients in C and C++ services.

```
#include "mqtthelper.h"

int hello_cb(void *notused, const char *topic, void *msg, int msg_len, void *user_data)
{
  return 0;
}

int main(int argc, char* argv[])
{
    int ret = 0;

    // Init the Mosquitto
    mqtt_helper_init();
    // Subscribe to topic
    ret = mqtt_helper_add("hello/world",      &hello_cb,       NULL, NULL);
    
    mqtt_helper_connection_monitor();
    
    // Send a message.
    const char* payload = "Let's make this greate";
    mqtt_helper_publish("hello/strange", payload, strlen(payload));
    
    while( true ) {
      // Do stuff.
    }
    mqtt_helper_cleanup();
    return 0;   
}
```

