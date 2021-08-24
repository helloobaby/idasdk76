/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2021 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

#ifndef _LLONG_HPP
#define _LLONG_HPP

//---------------------------------------------------------------------------
#if defined(_MSC_VER)

typedef unsigned __int64 ulonglong;
typedef          __int64 longlong;

#elif defined(__GNUC__)

typedef unsigned long long ulonglong;
typedef          long long longlong;

#endif

//---------------------------------------------------------------------------
#ifdef __cplusplus
inline constexpr longlong make_longlong(uint32 ll,int32 hh) { return ll | (longlong(hh) << 32); }
inline constexpr ulonglong make_ulonglong(uint32 ll,int32 hh) { return ll | (ulonglong(hh) << 32); }
inline uint32 low(const ulonglong &x)  { return uint32(x); }
inline uint32 high(const ulonglong &x) { return uint32(x>>32); }
inline uint32 low(const longlong &x)   { return uint32(x); }
inline int32  high(const longlong &x)  { return uint32(x>>32); }
#else
#define make_longlong(ll,hh)   (ll | (longlong(hh) << 32))
#define make_ulonglong(ll,hh)  (ll | (ulonglong(hh) << 32))
#endif

idaman THREAD_SAFE longlong ida_export llong_scan(
        const char *buf,
        int radix,
        const char **end);
#ifndef swap64
   idaman THREAD_SAFE ulonglong ida_export swap64(ulonglong);
#  ifdef __cplusplus
     inline longlong swap64(longlong x)
     {
       return longlong(swap64(ulonglong(x)));
     }
#  endif
#endif

//---------------------------------------------------------------------------
//      128 BIT NUMBERS
//---------------------------------------------------------------------------
#ifdef __HAS_INT128__

typedef unsigned __int128 uint128;
typedef          __int128 int128;

inline int128 make_int128(ulonglong ll,longlong hh) { return ll | (int128(hh) << 64); }
inline uint128 make_uint128(ulonglong ll,ulonglong hh) { return ll | (uint128(hh) << 64); }
inline ulonglong low(const uint128 &x)  { return ulonglong(x); }
inline ulonglong high(const uint128 &x) { return ulonglong(x>>64); }
inline ulonglong low(const int128 &x)   { return ulonglong(x); }
inline longlong  high(const int128 &x)  { return ulonglong(x>>64); }

#else
#ifdef __cplusplus
//-V:uint128:730 not all members of a class are initialized inside the constructor
class uint128
{
  ulonglong l;
  ulonglong h;
  friend class int128;
public:
  uint128(void)  {}
  uint128(uint x) { l = x; h = 0; }
  uint128(int x)  { l = x; h = (x < 0)? -1 : 0; }
  uint128(ulonglong x) { l = x; h = 0; }
  uint128(longlong x)  { l = x; h = (x < 0) ? -1 : 0; }
  uint128(ulonglong ll, ulonglong hh) { l = ll; h = hh; }
  friend ulonglong low (const uint128 &x) { return x.l; }
  friend ulonglong high(const uint128 &x) { return x.h; }
  friend uint128 operator+(const uint128 &x, const uint128 &y);
  friend uint128 operator-(const uint128 &x, const uint128 &y);
  friend uint128 operator/(const uint128 &x, const uint128 &y);
  friend uint128 operator%(const uint128 &x, const uint128 &y);
  friend uint128 operator*(const uint128 &x, const uint128 &y);
  friend uint128 operator|(const uint128 &x, const uint128 &y);
  friend uint128 operator&(const uint128 &x, const uint128 &y);
  friend uint128 operator^(const uint128 &x, const uint128 &y);
  friend uint128 operator>>(const uint128 &x, int cnt);
  friend uint128 operator<<(const uint128 &x, int cnt);
  uint128 &operator+=(const uint128 &y);
  uint128 &operator-=(const uint128 &y);
  uint128 &operator/=(const uint128 &y);
  uint128 &operator%=(const uint128 &y);
  uint128 &operator*=(const uint128 &y);
  uint128 &operator|=(const uint128 &y);
  uint128 &operator&=(const uint128 &y);
  uint128 &operator^=(const uint128 &y);
  uint128 &operator>>=(int cnt);
  uint128 &operator<<=(int cnt);
  uint128 &operator++(void);
  uint128 &operator--(void);
  friend uint128 operator+(const uint128 &x) { return x; }
  friend uint128 operator-(const uint128 &x);
  friend uint128 operator~(const uint128 &x) { return uint128(~x.l,~x.h); }
  friend int operator==(const uint128 &x, const uint128 &y) { return x.l == y.l && x.h == y.h; }
  friend int operator!=(const uint128 &x, const uint128 &y) { return x.l != y.l || x.h != y.h; }
  friend int operator> (const uint128 &x, const uint128 &y) { return x.h > y.h || (x.h == y.h && x.l >  y.l); }
  friend int operator< (const uint128 &x, const uint128 &y) { return x.h < y.h || (x.h == y.h && x.l <  y.l); }
  friend int operator>=(const uint128 &x, const uint128 &y) { return x.h > y.h || (x.h == y.h && x.l >= y.l); }
  friend int operator<=(const uint128 &x, const uint128 &y) { return x.h < y.h || (x.h == y.h && x.l <= y.l); }
};

//-V:int128:730 not all members of a class are initialized inside the constructor
class int128
{
  ulonglong l;
   longlong h;
  friend class uint128;
public:
  int128(void)  {}
  int128(uint x) { l = x; h = 0; }
  int128(int x)  { l = x; h = (x < 0) ? -1 : 0; }
  int128(ulonglong x) { l = x; h = 0; }
  int128(longlong x)  { l = x; h = (x < 0) ? -1 : 0; }
  int128(ulonglong ll, ulonglong hh) { l=ll; h=hh; }
  int128(const uint128 &x) { l=x.l; h=x.h; }
  friend ulonglong low (const int128 &x) { return x.l; }
  friend ulonglong high(const int128 &x) { return x.h; }
  friend int128 operator+(const int128 &x, const int128 &y);
  friend int128 operator-(const int128 &x, const int128 &y);
  friend int128 operator/(const int128 &x, const int128 &y);
  friend int128 operator%(const int128 &x, const int128 &y);
  friend int128 operator*(const int128 &x, const int128 &y);
  friend int128 operator|(const int128 &x, const int128 &y);
  friend int128 operator&(const int128 &x, const int128 &y);
  friend int128 operator^(const int128 &x, const int128 &y);
  friend int128 operator>>(const int128 &x, int cnt);
  friend int128 operator<<(const int128 &x, int cnt);
  int128 &operator+=(const int128 &y);
  int128 &operator-=(const int128 &y);
  int128 &operator/=(const int128 &y);
  int128 &operator%=(const int128 &y);
  int128 &operator*=(const int128 &y);
  int128 &operator|=(const int128 &y);
  int128 &operator&=(const int128 &y);
  int128 &operator^=(const int128 &y);
  int128 &operator>>=(int cnt);
  int128 &operator<<=(int cnt);
  int128 &operator++(void);
  int128 &operator--(void);
  friend int128 operator+(const int128 &x) { return x; }
  friend int128 operator-(const int128 &x);
  friend int128 operator~(const int128 &x) { return int128(~x.l,~x.h); }
  friend int operator==(const int128 &x, const int128 &y) { return x.l == y.l && x.h == y.h; }
  friend int operator!=(const int128 &x, const int128 &y) { return x.l != y.l || x.h != y.h; }
  friend int operator> (const int128 &x, const int128 &y) { return x.h > y.h || (x.h == y.h && x.l >  y.l); }
  friend int operator< (const int128 &x, const int128 &y) { return x.h < y.h || (x.h == y.h && x.l <  y.l); }
  friend int operator>=(const int128 &x, const int128 &y) { return x.h > y.h || (x.h == y.h && x.l >= y.l); }
  friend int operator<=(const int128 &x, const int128 &y) { return x.h < y.h || (x.h == y.h && x.l <= y.l); }
};

inline int128  make_int128(ulonglong ll, longlong hh) { return int128(ll, hh); }
inline uint128 make_uint128(ulonglong ll, longlong hh) { return uint128(ll, hh); }
idaman THREAD_SAFE void ida_export swap128(uint128 *x);

//---------------------------------------------------------------------------
inline uint128 operator+(const uint128 &x, const uint128 &y)
{
  ulonglong h = x.h + y.h;
  ulonglong l = x.l + y.l;
  if ( l < x.l )
    h = h + 1;
  return uint128(l,h);
}

//---------------------------------------------------------------------------
inline uint128 operator-(const uint128 &x, const uint128 &y)
{
  ulonglong h = x.h - y.h;
  ulonglong l = x.l - y.l;
  if ( l > x.l )
    h = h - 1;
  return uint128(l,h);
}

//---------------------------------------------------------------------------
inline uint128 operator|(const uint128 &x, const uint128 &y)
{
  return uint128(x.l | y.l, x.h | y.h);
}

//---------------------------------------------------------------------------
inline uint128 operator&(const uint128 &x, const uint128 &y)
{
  return uint128(x.l & y.l, x.h & y.h);
}

//---------------------------------------------------------------------------
inline uint128 operator^(const uint128 &x, const uint128 &y)
{
  return uint128(x.l ^ y.l, x.h ^ y.h);
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator+=(const uint128 &y)
{
  return *this = *this + y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator-=(const uint128 &y)
{
  return *this = *this - y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator|=(const uint128 &y)
{
  return *this = *this | y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator&=(const uint128 &y)
{
  return *this = *this & y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator^=(const uint128 &y)
{
  return *this = *this ^ y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator/=(const uint128 &y)
{
  return *this = *this / y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator%=(const uint128 &y)
{
  return *this = *this % y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator*=(const uint128 &y)
{
  return *this = *this * y;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator<<=(int cnt)
{
  return *this = *this << cnt;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator>>=(int cnt)
{
  return *this = *this >> cnt;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator++(void)
{
  if ( ++l == 0 )
    ++h;
  return *this;
}

//---------------------------------------------------------------------------
inline uint128 &uint128::operator--(void)
{
  if ( l == 0 )
    --h;
  --l;
  return *this;
}

//---------------------------------------------------------------------------
inline uint128 operator-(const uint128 &x)
{
  return ~x + 1;
}

#endif // ifdef __cplusplus
#endif // ifdef __HAS_INT128__

#endif // define _LLONG_HPP
