#ifndef RTC_CLIENT_H_
#define RTC_CLIENT_H_

#include "rtc_connection.h"

class RTCClient {
 public:
  virtual std::shared_ptr<RTCConnection> GetRTCConnection() const = 0;
};

#endif