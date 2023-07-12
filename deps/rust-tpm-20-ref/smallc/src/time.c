#include <time.h>
#include <errno.h>

const char __utc[] = "UTC";

time_t time(time_t *t)
{

	// TBD: need impl
	time_t current_time = 0;
	current_time = 1639526405;
	if (t != NULL)
	{
		*t = current_time;
	}
	return (time_t)1639526405;
}

extern int __secs_to_tm(long long t, struct tm *tm);

struct tm *gmtime(const time_t *t)
{
	static struct tm tm;
	if (__secs_to_tm(*t, &tm) < 0)
	{
		errno = EOVERFLOW;
		return 0;
	}
	tm.tm_isdst = 0;
	tm.__tm_gmtoff = 0;
	tm.__tm_zone = __utc;
	return &tm;
}

// Add an empty implementation for gettimeofday
struct timeval {
  long tv_sec;      /* time value, in seconds */
  long tv_usec;     /* time value, in microseconds */
};
struct timezone {
	int	tz_minuteswest;	/* minutes west of Greenwich */
	int	tz_dsttime;	/* type of dst correction */
};

int gettimeofday ( struct timeval * tv , struct timezone * tz ){
  return 1;
}
