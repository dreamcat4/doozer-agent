#include <stdint.h>

#include "utf8.h"

/**
 *
 */
int
utf8_put(char *out, int c)
{
  if(c == 0xfffe || c == 0xffff || (c >= 0xD800 && c < 0xE000))
    return 0;
  
  if (c < 0x80) {
    if(out)
      *out = c;
    return 1;
  }

  if(c < 0x800) {
    if(out) {
      *out++ = 0xc0 | (0x1f & (c >>  6));
      *out   = 0x80 | (0x3f &  c);
    }
    return 2;
  }

  if(c < 0x10000) {
    if(out) {
      *out++ = 0xe0 | (0x0f & (c >> 12));
      *out++ = 0x80 | (0x3f & (c >> 6));
      *out   = 0x80 | (0x3f &  c);
    }
    return 3;
  }

  if(c < 0x200000) {
    if(out) {
      *out++ = 0xf0 | (0x07 & (c >> 18));
      *out++ = 0x80 | (0x3f & (c >> 12));
      *out++ = 0x80 | (0x3f & (c >> 6));
      *out   = 0x80 | (0x3f &  c);
    }
    return 4;
  }
  
  if(c < 0x4000000) {
    if(out) {
      *out++ = 0xf8 | (0x03 & (c >> 24));
      *out++ = 0x80 | (0x3f & (c >> 18));
      *out++ = 0x80 | (0x3f & (c >> 12));
      *out++ = 0x80 | (0x3f & (c >>  6));
      *out++ = 0x80 | (0x3f &  c);
    }
    return 5;
  }

  if(out) {
    *out++ = 0xfc | (0x01 & (c >> 30));
    *out++ = 0x80 | (0x3f & (c >> 24));
    *out++ = 0x80 | (0x3f & (c >> 18));
    *out++ = 0x80 | (0x3f & (c >> 12));
    *out++ = 0x80 | (0x3f & (c >>  6));
    *out++ = 0x80 | (0x3f &  c);
  }
  return 6;
}


/**
 * Strict error checking UTF-8 decoder.
 * Based on the wikipedia article http://en.wikipedia.org/wiki/UTF-8
 * Checks for these errors:
 *
 * - Bytes 192, 193 and 245 - 255 must never appear.
 *
 * - Unexpected continuation byte.
 *
 * - Start byte not followed by enough continuation bytes.
 *
 * - A sequence that decodes to a value that should use a shorter
 *   sequence (an "overlong form").
 *
 */
int
utf8_get(const char **s)
{
    uint8_t c;
    int r, l, m;

    c = **s;
    *s = *s + 1;

    switch(c) {
    case 0 ... 127:
        return c;

    case 194 ... 223:
        r = c & 0x1f;
        l = 1;
        m = 0x80;
        break;

    case 224 ... 239:
        r = c & 0xf;
        l = 2;
        m = 0x800;
        break;

    case 240 ... 247:
        r = c & 0x7;
        l = 3;
        m = 0x10000;
        break;

    case 248 ... 251:
        r = c & 0x3;
        l = 4;
        m = 0x200000;
        break;

    case 252 ... 253:
        r = c & 0x1;
        l = 5;
        m = 0x4000000;
        break;
    default:
        return 0xfffd;
    }

    while(l-- > 0) {
        c = **s;
        if((c & 0xc0) != 0x80)
            return 0xfffd;
        *s = *s + 1;
        r = r << 6 | (c & 0x3f);
    }
    if(r < m)
        return 0xfffd; // overlong sequence

    return r;
}
