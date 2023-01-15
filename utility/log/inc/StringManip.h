#ifndef __StringManip_hh__
#define __StringManip_hh__


#include <string>
#include <stdexcept>
#include <mp/map>
using namespace std;

namespace StringManip
{
  void trim (string& ioStr);
  void total_trim (string& ioStr);
  void tolower (string& ioStr);
  void toupper (string& ioStr);
  void compress (string& ioStr, char cStr = ' ');   //Trim multiple occerence of a given character


  //* Codes/decodes a string into x-www-form-urlencoded format
  string URLencode (const string& iSrc);
  string URLdecode (const string& iStr);
  char   hexToChar (char iFirst, char iSecond);

  string hex2bin (const string& iTxt) throw (runtime_error);
  unsigned char hexDigit2uchar (unsigned char iC) throw (runtime_error);
  void uchar2HexDigit (unsigned char iC, char& un, char& ln);

  string escapeXML (const string& message, bool iSimple = false);

  void parseHdrLine (const string& iLine, pair<string,string>& oResult, bool iTolower = true);

  string IA5_decode (const string& iStr);
  string IA5_encode (const string& iStr);

  string toHex (const string& iStr);
  string makePrintable (const string& iStr);
  string unescapePrintable (const string& iStr) throw (runtime_error);

  void ntoh_16 (string& iStr);
  void hton_16 (string& iStr);

  long parseLong (const string& iStr);

  string itoa (int i, unsigned int radix = 10);
  void   itoa (string& oRes, int i, unsigned int radix = 10);

  string time2string (unsigned long t);
  void   time2string (string& oRes, unsigned long t);

  bool match (const string& str1, const string& str2);

  string expandMacros (const string& iStr, const map<char,string>& iChrMacros, const map<string,string>& iStrMacros);
  string getTagValue (const string& iTxt, const string& iTag);

  class Base64
  {
  public:
    static size_t estimateSize (const string& str);

    static void encode (const string& iStr, string& oStr);
    static void decode (const string& iStr, string& oStr) throw (runtime_error);

    static string encode (const string& iStr);
    static string decode (const string& iStr) throw (runtime_error);

  private:
    Base64 () {}

    static int    initializeBase64Tables ();
    int           getHexValue (int c) throw (runtime_error);
    static int    nextChar (const char*& str);

    static char base64encode [64];
    static int  base64decode [256];
    static char base64pad;
    static int  initialized;
  };

  string createWAPPush (const string& iURL, const string& iDescr) throw (runtime_error);
  bool isWapPush (string& iUDH);
  void getWapURLAndText (string& iText, string& oWapURL, string& oText)throw (runtime_error);
};


#endif
