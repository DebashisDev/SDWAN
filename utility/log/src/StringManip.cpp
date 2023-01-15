#include "StringManip.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include "MPctime.h"

///////////////////////////////////
string
StringManip::URLencode (const string& src)
///////////////////////////////////
{
  string encoded = "";

//  TheLog_v1 (Log::Debug, name(), "URL-encoding string <%s>...", src.c_str());

  /** To convert a string source <i>src</i>, each character is examined in turn:
       - The space character ' ' is converted into a plus sign '+'.
       - All other characters are converted into the 3-character string "%xy", where xy is the two-digit hexadecimal representation
         of the lower 8-bits of the character.
       - The ASCII characters 'a' through 'z', 'A' through 'Z', and '0' through '9' remain the same.
  */
  for (unsigned int i = 0; i < src.length(); ++i)
  {
    if (src[i] == ' ')
    {
      encoded += "+";
   }
   else if ( !( (src[i] >= '0' && src[i] <= '9') || (src[i] >= 'A' && src[i] <= 'Z') || (src[i] >= 'a' && src[i] <= 'z') ) )
   {
     encoded += "%";
     char hex[32];
     sprintf (hex, "%2.2X", int (src[i]) & 0x0FF);
     hex[3] = '\0';
     encoded += hex;
   }
   else
   {
     encoded += src[i];
    }
  }

//  TheLog_v2 (Log::Debug, name(), "String <%s> URL-encoded as <%s>", src.c_str(), encoded.c_str());
  return encoded;
}


////////////////////////////////////////////////////
string
StringManip::URLdecode (const string& iStr)
////////////////////////////////////////////////////
{
  string res;

  for (string::const_iterator iter = iStr.begin ();
       iter != iStr.end ();
       iter++)
    {
      switch (*iter)
      {
        case '+':
          res.append (1, ' ');
          break;

        case '%':
        {
          iter++;
          if (iter == iStr.end ())
          {
            res.append (1, '%');
            return res;
          }

          char c1 = *iter;

          iter++;
          if (iter == iStr.end ())
          {
            res.append (1, '%');
            res.append (1, c1);
            return res;
          }

          char c2 = *iter;
          res.append (1, hexToChar (c1, c2));
        }
        break;

        default:
          res.append (1, *iter);
          break;
    }
  }

  return res;
}


////////////////////////////////////////////////////
char
StringManip::hexToChar (char iFirst, char iSecond)
////////////////////////////////////////////////////
{
  char digit;

  digit = (iFirst >= 'A' ? ((iFirst & 0xDF) - 'A') + 10 : (iFirst - '0'));
  digit <<= 4;
  digit += (iSecond >= 'A' ? ((iSecond & 0xDF) - 'A') + 10 : (iSecond - '0'));

  return digit;
}


////////////////////////////////////////////////
void
StringManip::trim (string& ioStr)
////////////////////////////////////////////////
{
  bool done = false;

  // trim beginning
  while ((ioStr.empty () == false) && (!done))
  {
    if
    (
      (*ioStr.begin () == ' ') ||
      (*ioStr.begin () == '\t' )
    )
    {
      ioStr.erase (ioStr.begin ());
    }
    else
    {
      done = true;
    }
  }

  // trim ending
  done = false;
  while ((ioStr.empty () == false) && (!done))
  {
    if
    (
      (*ioStr.rbegin () == ' ') ||
      (*ioStr.rbegin () == '\t' )
    )
    {
      ioStr.erase (ioStr.size () - 1);
    }
    else
    {
      done = true;
    }
  }
}


////////////////////////////////////////////////
void
StringManip::total_trim (string& ioStr)
////////////////////////////////////////////////
{
  unsigned char buf [ioStr.size () + 1];
  memcpy (buf, ioStr.data (), ioStr.size ());
  buf [ioStr.size ()] = '\0';
  unsigned char* begin = buf;
  unsigned char* end   = begin + ioStr.size () - 1;

  // trim beginning
  while
  (
    (*begin == ' ' || *begin == '\t' || *begin == '\n' || *begin == '\r' ) &&
    (begin != end)
  )
  {
    begin++;
  }

  if (begin == end)
  {
    if (*begin == ' ' || *begin == '\t' || *begin == '\n' || *begin == '\r')
    {
      ioStr = "";
    }
    else
    {
      ioStr = (const char*)(begin);
    }

    return;
  }

  // trim end
  while
  (
    (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r' ) &&
    (begin != end)
  )
  {
    *end = '\0';
    end--;
  }

  if (begin == end)
  {
    if (*begin == ' ' || *begin == '\t' || *begin == '\n' || *begin == '\r')
    {
      ioStr = "";
    }
    else
    {
      ioStr = (const char*)(begin);
    }

    return;
  }

  ioStr = (const char*)(begin);
}


////////////////////////////////////////////////
void
StringManip::tolower (string& ioStr)
////////////////////////////////////////////////
{
  for (string::iterator iter = ioStr.begin ();
       iter != ioStr.end ();
       iter++)
  {
    *iter = ::tolower (*iter);
  }
}

////////////////////////////////////////////////
void
StringManip::toupper (string& ioStr)
////////////////////////////////////////////////
{
  for (string::iterator iter = ioStr.begin ();
       iter != ioStr.end ();
       iter++)
  {
    *iter = ::toupper (*iter);
  }
}



/////////////////////////////
string
StringManip::hex2bin (const string& iTxt)
throw (runtime_error)
/////////////////////////////
{
  unsigned in_size = iTxt.size ();

  if (in_size % 2 != 0)
  {
    // size not even
    throw runtime_error ((string ("Size of HEX text is not even:") + iTxt).c_str ());
  }

  char* res = new char [(in_size / 2) + 2];
  char c;

  const char* iptr = iTxt.data ();
  char* optr = res;

  for (unsigned i = 0; i < in_size; i += 2)
  {
    try
    {
      c = hexDigit2uchar (*iptr) * 16 + hexDigit2uchar (*(iptr + 1));
      *optr = c;

      iptr += 2;
      optr++;
    }
    catch (runtime_error& mut)
    {
      throw runtime_error (( string(mut.what()) + string(". Text:") + iTxt).c_str());
    }
  }

  string s (res, in_size / 2);
  delete [] res;
  return s;
}


////////////////////////////
void
StringManip::uchar2HexDigit (unsigned char iC, char& un, char& ln)
/////////////////////////////
{
  unsigned char hexc = iC & ((unsigned char)(0x0F));

  switch (hexc)
  {
    case 0x00: ln = '0'; break;
    case 0x01: ln = '1'; break;
    case 0x02: ln = '2'; break;
    case 0x03: ln = '3'; break;
    case 0x04: ln = '4'; break;
    case 0x05: ln = '5'; break;
    case 0x06: ln = '6'; break;
    case 0x07: ln = '7'; break;
    case 0x08: ln = '8'; break;
    case 0x09: ln = '9'; break;
    case 0x0A: ln = 'A'; break;
    case 0x0B: ln = 'B'; break;
    case 0x0C: ln = 'C'; break;
    case 0x0D: ln = 'D'; break;
    case 0x0E: ln = 'E'; break;
    case 0x0F: ln = 'F'; break;
  }

  hexc = (iC >> 4) & ((unsigned char)(0x0F));

  switch (hexc)
  {
    case 0x00: un = '0'; break;
    case 0x01: un = '1'; break;
    case 0x02: un = '2'; break;
    case 0x03: un = '3'; break;
    case 0x04: un = '4'; break;
    case 0x05: un = '5'; break;
    case 0x06: un = '6'; break;
    case 0x07: un = '7'; break;
    case 0x08: un = '8'; break;
    case 0x09: un = '9'; break;
    case 0x0A: un = 'A'; break;
    case 0x0B: un = 'B'; break;
    case 0x0C: un = 'C'; break;
    case 0x0D: un = 'D'; break;
    case 0x0E: un = 'E'; break;
    case 0x0F: un = 'F'; break;
  }
}


////////////////////////////
unsigned char
StringManip::hexDigit2uchar (unsigned char iC)
throw (runtime_error)
/////////////////////////////
{
  switch (iC)
  {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      return iC - '0';

    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
      return iC - 'a' + 10;

    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
      return iC - 'A' + 10;

    default:
      throw runtime_error ((string ("char [") + (char)(iC) + "] not allowed in HEX format").c_str ());
  }

  // unreachable
  return 0;
}


////////////////////////////////////////////////
void
StringManip::parseHdrLine (const string&        iLine,
                           pair<string,string>& oResult,
                           bool                 iTolower)
////////////////////////////////////////////////
{
  string rem (iLine);

  oResult.first = "";
  oResult.second = "";
  StringManip::trim (rem);
  string::size_type pos = iLine.find (':');

  if (pos == string::npos)
  {
    if (iTolower)
    {
      StringManip::tolower (rem);
    }

    oResult.first = rem;
    return;
  }

  oResult.first = rem.substr (0, pos);
  rem = rem.substr (pos + 1);

  StringManip::trim (oResult.first);

  if (iTolower)
  {
    StringManip::tolower (oResult.first);
  }

  oResult.second = rem;
  StringManip::trim (oResult.second);
}


///////////////////////////////////////
string
StringManip::escapeXML (const string& iTxt, bool iSimple)
///////////////////////////////////////
{
  string str;
  char b [32];
  unsigned char c;

  for (string::const_iterator iter = iTxt.begin ();
       iter != iTxt.end ();
       iter++)
  {
    c = *iter;

    switch (c)
    {
      case '&':  str += "&amp;";  break;
      case '<':  str += "&lt;";   break;
      case '>':  str += "&gt;";   break;
      case '\"': str += "&quot;"; break;
      case '\'': str += "&apos;"; break;

      default:
      {
        if (!iSimple)
        {
          if      (c < ' ') {sprintf (b, "&#%02d;", c); str += b;}
          else if (c > 127) {sprintf (b, "&#%02d;", c); str += b;}
          else str.append (1, c);
        }
        else
        {
          str.append (1, c);
        }
      }
    }
  }

  return str;
}


/////////////////////////////////////////////
string
StringManip::IA5_decode (const string& iStr)
/////////////////////////////////////////////
{
  const unsigned char* in = (const unsigned char*)(iStr.data ());
  int bits_left = 0;
  unsigned char  leftover = 0x00;
  string res;
  unsigned len = iStr.size ();

  for (; len > 0; len--, in++)
  {
    res += ((*in << bits_left) & 0x7F) | leftover;
    leftover =  (*in >> (7 - bits_left));

    if (++bits_left >= 7)
    {
      res += leftover;
      leftover = 0x00;
      bits_left = 0;
    }
  }

  return res;
}


/////////////////////////////////////////////
string
StringManip::IA5_encode (const string& iStr)
/////////////////////////////////////////////
{
  string res;
  unsigned len = iStr.size ();
  const unsigned char* in = (const unsigned char*)(iStr.data ());

  if (len <= 0)
  {
    return 0;
  }

  int    k = 0;
  int    bits_left = 0;
  unsigned char  ch0 = (in[0] & 0x7F);

  for (; len > 0; len--, in++)
  {
    unsigned char  ch1 = ((len > 1) ? in[1] : 0) & 0x7F;

    if (bits_left < 7)
    {
      res += ch0 | (ch1 << (7 - bits_left));
      k++;
      ch0 = (ch1 >> (++bits_left));
    }
    else
    {
      ch0 = ch1;
      bits_left = 0;
    }
  }

  return res;
}


/////////////////////////////////////////////
string
StringManip::toHex (const string& iStr)
/////////////////////////////////////////////
{
  string res;
  char* b = new char [iStr.size () * 2 + 2];
  char* ptr = b;

  b [iStr.size () * 2] = 0;

  for (string::const_iterator iter = iStr.begin ();
       iter != iStr.end ();
       iter++, ptr += 2)
  {
    uchar2HexDigit ((*iter) & 0x0FF, *ptr, *(ptr + 1));
  }

  res = b;
  delete [] b;
  return res;
}

/////////////////////////////////////////////
string
StringManip::makePrintable (const string& iStr)
/////////////////////////////////////////////
{
  char* b = new char [iStr.size () * 4 + 100];
  char* ptr = b;
  unsigned size = iStr.size ();
  const char* bptr = iStr.data ();

  for (unsigned i = 0; i < size; i++)
  {
    char c = *bptr++;

    if (c == '\\')
    {
      *ptr++ = '\\';
      *ptr++ = '\\';
    }
    else if (::isprint (c))
    {
      *ptr++ = c;
    }
    else
    {
      *ptr++ = '\\';
      *ptr++ = 'x';
      uchar2HexDigit ((c & 0xFF), *ptr, *(ptr + 1));
      ptr += 2;
    }
  }

  *ptr = 0;
  string res (b);
  delete [] b;

  return res;
}


/////////////////////////////////////////////
string
StringManip::unescapePrintable (const string& iStr)
throw (runtime_error)
/////////////////////////////////////////////
{
  string res;

  for (string::const_iterator iter = iStr.begin ();
       iter != iStr.end ();
       iter++)
  {
    if (*iter == '\\')
    {
      iter++; if (iter == iStr.end ()){return res;}
      if (*iter != 'x')
      {
        res += *iter;
      }
      else
      {
        iter++; if (iter == iStr.end ()){return res;}
        unsigned char c1 = hexDigit2uchar (*iter);
        iter++; if (iter == iStr.end ()){return res;}
        unsigned char c0 = hexDigit2uchar (*iter);

        res += (unsigned char)((c1 << 4) + c0);
      }
    }
    else
    {
      res += *iter;
    }
  }

  return res;
}

/////////////////////////////////////////////
void
StringManip::hton_16 (string& iStr)
/////////////////////////////////////////////
{
  unsigned t = 0x11223344;
  if (t == htonl (t))
  {
    // host is MSB, as well as Network order
  }
  else
  {
    // host is LSB
    unsigned size = iStr.size ();
    string::value_type c;

    for (unsigned i = 0; i < size; i += 2)
    {
      c = iStr [i];
      iStr [i] = iStr [i + 1];
      iStr [i + 1] = c;
    }
  }
}


/////////////////////////////////////////////
void
StringManip::ntoh_16 (string& iStr)
/////////////////////////////////////////////
{
  hton_16 (iStr);
}


/////////////////////////////////////////////
long
StringManip::parseLong (const string& iStr)
/////////////////////////////////////////////
{
  return atol (iStr.c_str ());
}


namespace StringManip
{
  const char* itoaChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
};


/////////////////////////////////////////////
string
StringManip::itoa (int i, unsigned int radix)
/////////////////////////////////////////////
{
  string res;
  StringManip::itoa (res, i, radix);
  return res;
}


/////////////////////////////////////////////
void
StringManip::itoa (string& oRes, int i, unsigned int radix)
/////////////////////////////////////////////
{
  if (i == 0)
  {
    oRes = "0";
  }
  else
  {
    const int cBuffSize = 32;
    char buff [cBuffSize];

    bool neg = (i < 0);
    if (neg)
    {
      i = -i;
    }

    // Set chars from the end of the buffer
    char* ptr = &buff [cBuffSize - 1];
    *ptr = 0;

    while (i)
    {
      ptr--;
      *ptr = itoaChars [i%radix];
      i = i / radix;
    }

    if (neg)
    {
      ptr--;
      *ptr = '-';
    }

    oRes = ptr;
  }
}


///////////////////////////////////////
string
StringManip::time2string (unsigned long t)
///////////////////////////////////////
{
  string res;
  StringManip::time2string (res, t);
  return res;
}


///////////////////////////////////////
void
StringManip::time2string (string& oRes, unsigned long t)
///////////////////////////////////////
{
  if (t == 0)
  {
    oRes = "null";
    return;
  }

  time_t tt = (time_t)(t);
//  oRes = mp_ctime (&tt);
//  oRes.erase (oRes.size () - 1);
}


///////////////////////////////////////
string
StringManip::expandMacros (const string&             iStr,
                           const map<char, string>&  iChrMacros,
                           const map<string,string>& iStrMacros)
///////////////////////////////////////
{
  string res;

  for (string::const_iterator iter = iStr.begin ();
       iter != iStr.end ();
       iter++)
  {
    if (*iter == '%')
    {
      iter++;

      if (iter == iStr.end ())
      {
        res += '%';
        return res;
      }

      // is it a string one?
      if (*iter == '{')
      {
        // get the key
        string key;

        iter++;
        while ((iter != iStr.end ()) && (*iter != '}'))
        {
          key += *iter;
          iter++;
        }

        if (iter == iStr.end ())
        {
          return res;
        }

        map<string, string>::const_iterator m_iter = iStrMacros.find (key);

        if (m_iter != iStrMacros.end ())
        {
          res.append (m_iter->second);
        }
      }
      else
      {
        map<char, string>::const_iterator m_iter = iChrMacros.find (*iter);

        if (m_iter == iChrMacros.end ())
        {
          res += *iter;
        }
        else
        {
          res.append (m_iter->second);
        }
      }
    }
    else
    {
      res += *iter;
    }
  }

  return res;
}


//////////////////////////////////////////
bool
StringManip::match (const string& str1, const string& str2)
//////////////////////////////////////////
{
  if (str1.length () < str2.length ())
  {
    return false;
  }

  if (memcmp (str2.data (), str1.data (), str2.length ()))
  {
    return false;
  }

  return true;
}


//////////////////////////////////////////
string
StringManip::getTagValue (const string& iTxt, const string& iTag)
//////////////////////////////////////////
{
  string::size_type openTagBeginPos = iTxt.find ("<" + iTag + ">");

  if (openTagBeginPos == string::npos)
  {
    // no opening tag: try <tag ...>
    openTagBeginPos = iTxt.find ("<" + iTag + " ");
  }

  if (openTagBeginPos == string::npos)
  {
    // no opening tag: give up
    return "";
  }

  string::size_type openTagEndPos = iTxt.find ('>', openTagBeginPos) + 1;
  string::size_type closeTagBeginPos = iTxt.find (string ("</") + iTag + ">", openTagEndPos);

  if (closeTagBeginPos == string::npos)
  {
    // no closing tag
    return "";
  }

  // extract
  string res = iTxt.substr (openTagEndPos, closeTagBeginPos - openTagEndPos);
  return res;
}


char StringManip::Base64::base64encode[64];
int  StringManip::Base64::base64decode[256];
char StringManip::Base64::base64pad = '=';


///////////////////////////////////////////////////////////////////////////////////
int
StringManip::Base64::initializeBase64Tables()
///////////////////////////////////////////////////////////////////////////////////
{
  int i;

  // initialize the encoding table
  for (i = 0; i < 26; ++i)
  {
    base64encode[i] = 'A' + i;
    base64encode[26 + i] = 'a' + i;
  }

  for (i = 0; i < 10; ++i)
    base64encode[52 + i] = '0' + i;

  base64encode[62] = '+';
  base64encode[63] = '/';


  // initialize the decoding table
  for (i = 0; i < 256; ++i)
    base64decode[i] = (char)0x80;
  for (i = 'A'; i <= 'Z'; ++i)
    base64decode[i] = i - 'A';
  for (i = 'a'; i <= 'z'; ++i)
    base64decode[i] = 26 + i - 'a';
  for (i = '0'; i <= '9'; ++i)
    base64decode[i] = 52 + i - '0';

  base64decode[(int)('+')] = 62;
  base64decode[(int)('/')] = 63;
  base64decode[(int)(base64pad)] = 0;

  return 1;
}


///////////////////////////////////////////////////////////////////////////////////
int StringManip::Base64::initialized = StringManip::Base64::initializeBase64Tables();


///////////////////////////////////////////////////////////////////////////////////
int
StringManip::Base64::nextChar(const char*& str)
///////////////////////////////////////////////////////////////////////////////////
{
  int c = 0;

  // skip over white space
  while (isspace(*str))
    ++str;

  // only increment pointer if
  // we're not at the end of string
  if ((c = *str))
    ++str;

  return c;
}


///////////////////////////////////////////////////////////////////////////////////
size_t
StringManip::Base64::estimateSize (const string& str)
///////////////////////////////////////////////////////////////////////////////////
{
  return (str.size () / 4) * 3 + 3;
}


///////////////////////////////////////////////////////////////////////////////////
void
StringManip::Base64::decode (const string& iStr, string& oStr)
throw (runtime_error)
///////////////////////////////////////////////////////////////////////////////////
{
  bool done = false;
  const char *str = iStr.data ();

  while (!done)
  {
    int   in[4];
    char  out[3];
    int   valid = 3;

    in[0] = nextChar(str);
    in[1] = nextChar(str);
    in[2] = nextChar(str);
    in[3] = nextChar(str);

    if (in[0] == 0)
      break;

    if (in[2] == base64pad)
      valid = 1;
    else if (in[3] == base64pad)
      valid = 2;

    in[0] = base64decode[in[0]];
    in[1] = base64decode[in[1]];
    in[2] = base64decode[in[2]];
    in[3] = base64decode[in[3]];

    if (in[0] == 0x80 ||
      in[1] == 0x80 ||
      in[2] == 0x80 ||
      in[3] == 0x80)
      throw runtime_error ("Invalid character in base64 string.");

    out[0] = (in[0] << 2) | (in[1] >> 4);
    out[1] = (in[1] << 4) | (in[2] >> 2);
    out[2] = (in[2] << 6) |  in[3];

    if (valid == 1)
    {
      oStr += (out[0]);
      done = true;
    }
    else if (valid == 2)
    {
      oStr += (out[0]);
      oStr += (out[1]);
      done = true;
    }
    else // valid == 3
    {
      oStr += (out[0]);
      oStr += (out[1]);
      oStr += (out[2]);
    }
  }
}


///////////////////////////////////////////////////////////////////////////////////
void
StringManip::Base64::encode (const string& iStr, string& oStr)
///////////////////////////////////////////////////////////////////////////////////
{
  unsigned size = iStr.size ();
  const unsigned char *in = (const unsigned char *)(iStr.data ());

  while (size >= 3)
  {
    oStr += (base64encode[in[0] >> 2]);
    oStr += (base64encode[((in[0] & 3) << 4) | (in[1] >> 4)]);
    oStr += (base64encode[((in[1] & 0xF) << 2) | (in[2] >> 6)]);
    oStr += (base64encode[in[2] & 0x3F]);
    size -= 3;
    in += 3;
  }

  if (size == 2)
  {
    oStr += (base64encode[in[0] >> 2]);
    oStr += (base64encode[((in[0] & 3) << 4) | (in[1] >> 4)]);
    oStr += (base64encode[(in[1] & 0xF) << 2]);
    oStr += (base64pad);
  }
  else if (size == 1)
  {
    oStr += (base64encode[in[0] >> 2]);
    oStr += (base64encode[(in[0] & 3) << 4]);
    oStr += (base64pad);
    oStr += (base64pad);
  }
}


///////////////////////////////////////////////////////////////////////////////////
string
StringManip::Base64::decode (const string& iStr)
throw (runtime_error)
///////////////////////////////////////////////////////////////////////////////////
{
  string res;
  decode (iStr, res);
  return res;
}


///////////////////////////////////////////////////////////////////////////////////
string
StringManip::Base64::encode (const string& iStr)
///////////////////////////////////////////////////////////////////////////////////
{
  string res;
  encode (iStr, res);
  return res;
}


///////////////////////////////////////////////////////////////////////////////////
inline
int
StringManip::Base64::getHexValue (int c)
throw (runtime_error)
///////////////////////////////////////////////////////////////////////////////////
{
  switch (c)
  {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'A': case 'a': return 10;
    case 'B': case 'b': return 11;
    case 'C': case 'c': return 12;
    case 'D': case 'd': return 13;
    case 'E': case 'e': return 14;
    case 'F': case 'f': return 15;
    default:
    {
      char b [128];
      sprintf (b, "Invalid hex character: %c(%d)", c, c);
      throw runtime_error (b);
    }
  }
}


///////////////////////////////////////////////////////////////////////////////////
string
StringManip::createWAPPush (const string& iURL, const string& iDescr)
throw (runtime_error)
///////////////////////////////////////////////////////////////////////////////////
{
  // 0605040B8423F0010601AE02056A0045
  // C60C033231322E3233392E31372E3139
  // 332F702E703F703D3036303430333030
  // 30313536333033373233323438300008
  // 010348617A20636C69636B2061717569
  // 20706172612064657363617267617200
  // 0101
  string protocol;
  string src;

  if (StringManip::match (iURL, "http://"))
  {
    src = iURL.substr (7); // iURL.substr (strlen ("http://"));
    protocol = "0C";
  }
  else
  {
    src = iURL;
    protocol = "0B";
  }

  string b =
    "0605040B8423F0"
    "01" //Transaction ID
    "06" //PDU Type (push)
    //"04" //Headers Length (content-type + headers)
    "01" //Length of content type
    "AE" //Content-Type:
         //"81" //Charset
         //"EA" //UTF-8
    //End Headers
    //si_binary_output
    "02" //Version number (wbxml_version)
    "05" //Unknown Public Identifier (si_public_id)
    "6A" //charset= (sibxml->charset)
    "00" //String table length
    "45" //<si>
    "C6" //<indication...
    + protocol +
    "03" + StringManip::toHex (src) + "00" //href=$url
    //"11030100" //si-id=
    "08" //action="signal-high"
    //"0AC30720011021200223" //created=
    //"88068104FFFFFFFF" //valid=
    "01" //end indication params
    "03" + StringManip::toHex (iDescr) + "00"  //* @todo filter descr, just in case?
    "01" //</indication>
    "01"; //</si>

  return b;
}

///////////////////////////////////////////////////////
bool
StringManip::isWapPush (string& iUDH)
///////////////////////////////////////////////////////
{
	// fall back to UDH-based guessing

	return false;
}

///////////////////////////////////////////////////////////
void
StringManip::getWapURLAndText (string& iText, string& oWapURL, string& oText)
throw (runtime_error)
///////////////////////////////////////////////////////////
{
	oWapURL = oText = "";

	//Get the text without UDH
	string text = iText;
	unsigned i = 0;

	string pair = text.substr(i, 2);

	try{
		//Skip byte pairs until we get the "indication" tag (C6)
		while (((i+1) < text.length()) && (pair != "C6")){
			i += 2;
			pair = text.substr (i, 2);
		}

		if ((i+1) >= text.length ())
		{
		  //Indication tag missing. Just return
		  return;
		}

		i += 2;
		pair = text.substr (i, 2);
		//Do ASCII character until the end of the text
		if (pair == "0C"){
			oWapURL += "http://";
			i += 2;
			pair = text.substr (i, 2);
		}
		else if (pair == "0D"){
			oWapURL += "http://www.";
			i += 2;
			pair = text.substr (i, 2);
		}
		else if (pair == "0E"){
			oWapURL += "https://";
			i += 2;
			pair = text.substr (i, 2);
		}
		else if (pair == "0F"){
			oWapURL += "https://www.";
			i += 2;
			pair = text.substr (i, 2);
		}
		if (pair == "03"){
			i += 2;
			pair = text.substr(i, 2);
		}
		while (pair != "00"){
			oWapURL += StringManip::hexToChar(pair[0], pair[1]);
			i += 2;
			pair = text.substr (i, 2);
		}
		i += 2;
		pair = text.substr (i, 2);
		if (pair == "85"){
			oWapURL += ".com/";
			i += 2;
			pair = text.substr (i, 2);
		}
		else if (pair == "86"){
			oWapURL += ".edu/";
			i += 2;
			pair = text.substr (i, 2);
		}
		else if (pair == "87"){
			oWapURL += ".net/";
			i += 2;
			pair = text.substr (i, 2);
		}
		else if (pair == "88"){
			oWapURL += ".org/";
			i += 2;
			pair = text.substr (i, 2);
		}
		if (pair == "03"){//The following is the path to the http file
			i += 2;
			pair = text.substr (i, 2);
			while (pair != "00"){
				oWapURL += StringManip::hexToChar(pair[0], pair[1]);
				i+=2;
				pair = text.substr (i, 2);
			}
			i += 2;
			pair = text.substr (i, 2);
		}
		if (pair == "0A"){//The tag has an atribute called "created" (time of creation)
			i += 2;
			pair = text.substr(i, 2);
			if (pair == "C3"){//The following is a date:
				i += 2;
				pair = text.substr (i, 2);
				if (pair == "07"){ //The date length is 7 bytes, so we advance 14 characters (plus the current two)
					i += 16;
				}
				else if (pair == "04"){ //The date length is 4 bytes, so we advance 8 characters (plus the current two)
					i += 10;
				}
				pair = text.substr (i, 2);
			}
		}
		if (pair == "10"){//We have a si-expires attribute
			i += 2;
			pair = text.substr (i, 2);
			if (pair == "C3"){//The following is a date
				i += 2;
				pair += text.substr (i, 2);
				if (pair == "07"){ //The date length is 7 bytes, so we advance 14 characters (plus the current two)
					i += 16;
				}
				else if (pair == "04"){ //The date length is 4 bytes, so we advance 8 characters (plus the current two)
					i += 10;
				}
				pair = text.substr (i, 2);
			}
		}
		if (pair == "01"){ //The end of the <indication> attribute list
			i += 2;
			pair = text.substr (i, 2);
		}
		else{//Advance untill the end of the <indication> attribute list
			while ( pair != "01" ){
				i += 2;
				pair = text.substr(i, 2);
			}
			//Advance to the next pair:
			i += 2;
			pair = text.substr(i, 2);
		}
		if (pair == "03"){//The next is the text of the message
			i += 2;
			pair = text.substr (i, 2);
			//Get the text until we find the "00" byte pair, followed by the "01" byte pair
			while (pair != "00"){
				oText += StringManip::hexToChar(pair[0], pair[1]);
				i += 2;
				pair = text.substr (i, 2);
			}
		}
	}
	catch (runtime_error& e){
		throw (e);
	}
}


////////////////////////////////////////////////
void
StringManip::compress (string& ioStr,char cStr)
////////////////////////////////////////////////
{
  bool found = true;
  string str_double(2,cStr);
  string str(1,cStr);
  while(found)
  {
    int i = ioStr.find(str_double); //Search for 2 spaces
    if(i != string::npos)
    {
      ioStr.replace(i, 2, str);
    }
    else
      found = false;
  }
}

