#define _POSIX_C_SOURCE 200809L

#include <moonbit.h>
#include <stdint.h>
#include <time.h>

MOONBIT_FFI_EXPORT
int64_t moonbit_rtc_monotonic_milliseconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
    return -1;
  }
  return ((int64_t)value.tv_sec * INT64_C(1000)) +
         ((int64_t)value.tv_nsec / INT64_C(1000000));
}

MOONBIT_FFI_EXPORT
int64_t moonbit_rtc_realtime_nanoseconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_REALTIME, &value) != 0) {
    return 0;
  }
  return ((int64_t)value.tv_sec * INT64_C(1000000000)) +
         (int64_t)value.tv_nsec;
}
