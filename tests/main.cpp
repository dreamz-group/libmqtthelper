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

#include <gtest/gtest.h>
#include "../mqtthelper.c"

static int called = 0;

static int cb(void *local_id, const char *topic, void *msg, int msg_len, void *user_data)
{
    called++;
    return 0;
}

TEST(mqtthelper, topic_test1)
{
    called = 0;
    mqtt_helper_add( "x/#", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd", msg, strlen(msg));
    mqtt_helper_del("x/#");
    EXPECT_TRUE( called == 1 && t == 1);
}

TEST(mqtthelper, topic_test2)
{
    called = 0;
    mqtt_helper_add( "x/#", cb, NULL, NULL );
    mqtt_helper_add( "x/b/#", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/b/asd", msg, strlen(msg));
    mqtt_helper_del("x/#");
    mqtt_helper_del("x/b/#");
    EXPECT_TRUE( called == 2 && t == 2);
}

TEST(mqtthelper, topic_test3)
{
    called = 0;
    mqtt_helper_add( "x/x/#", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd", msg, strlen(msg));
    mqtt_helper_del("x/x/#");
    EXPECT_TRUE( called == 0 && t == 0);
}

TEST(mqtthelper, topic_test4)
{
    called = 0;
    mqtt_helper_add( "x/+", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd", msg, strlen(msg));
    mqtt_helper_del("x/+");
    EXPECT_TRUE( called == 1 && t == 1);
}

TEST(mqtthelper, topic_test5)
{
    called = 0;
    mqtt_helper_add( "x/+/x", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd/x", msg, strlen(msg));
    mqtt_helper_del("x/+/x");
    EXPECT_TRUE( called == 1 && t == 1);
}

TEST(mqtthelper, topic_test6)
{
    called = 0;
    mqtt_helper_add( "x/+/x", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd/y", msg, strlen(msg));
    mqtt_helper_del("x/+/x");
    EXPECT_TRUE( called == 0 && t == 0);
}

TEST(mqtthelper, topic_test7)
{
    called = 0;
    mqtt_helper_add( "x/+/y/+/z", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd/y/adf/z", msg, strlen(msg));
    mqtt_helper_del("x/+/y/+/z");
    EXPECT_TRUE( called == 1 && t == 1);
}

TEST(mqtthelper, topic_test8)
{
    called = 0;
    mqtt_helper_add( "x/+/y/#", cb, NULL, NULL );
    const char* msg = "test";
    int t = mqtt_helper_trigger( "x/asd/y/adf/z", msg, strlen(msg));
    mqtt_helper_del("x/+/y/#");
    EXPECT_TRUE( called == 1 && t == 1);
}

int main(int argc, char* argv[])
{
    mqtt_helper_init();
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}