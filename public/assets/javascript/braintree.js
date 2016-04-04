/*!
 * Braintree End-to-End Encryption Library
 * https://www.braintreepayments.com
 * Copyright (c) 2009-2014 Braintree, a division of PayPal, Inc.
 *
 * JSBN
 * Copyright (c) 2005  Tom Wu
 *
 * Both Licensed under the MIT License.
 * http://opensource.org/licenses/MIT
 *
 * ASN.1 JavaScript decoder
 * Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>
 * Licensed under the ISC License.
 * http://opensource.org/licenses/ISC
 */

(function () {

// ASN.1 JavaScript decoder
// Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

function Stream(enc, pos) {
    if (enc instanceof Stream) {
        this.enc = enc.enc;
        this.pos = enc.pos;
    } else {
        this.enc = enc;
        this.pos = pos;
    }
}
Stream.prototype.get = function(pos) {
    if (pos == undefined)
        pos = this.pos++;
    if (pos >= this.enc.length)
        throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;
    return this.enc[pos];
}
Stream.prototype.hexDigits = "0123456789ABCDEF";
Stream.prototype.hexByte = function(b) {
    return this.hexDigits.charAt((b >> 4) & 0xF) + this.hexDigits.charAt(b & 0xF);
}
Stream.prototype.hexDump = function(start, end) {
    var s = "";
    for (var i = start; i < end; ++i) {
        s += this.hexByte(this.get(i));
        switch (i & 0xF) {
        case 0x7: s += "  "; break;
        case 0xF: s += "\n"; break;
        default:  s += " ";
        }
    }
    return s;
}
Stream.prototype.parseStringISO = function(start, end) {
    var s = "";
    for (var i = start; i < end; ++i)
        s += String.fromCharCode(this.get(i));
    return s;
}
Stream.prototype.parseStringUTF = function(start, end) {
    var s = "", c = 0;
    for (var i = start; i < end; ) {
        var c = this.get(i++);
        if (c < 128)
            s += String.fromCharCode(c);
        else if ((c > 191) && (c < 224))
            s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
        else
            s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
        //TODO: this doesn't check properly 'end', some char could begin before and end after
    }
    return s;
}
Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
Stream.prototype.parseTime = function(start, end) {
    var s = this.parseStringISO(start, end);
    var m = this.reTime.exec(s);
    if (!m)
        return "Unrecognized time: " + s;
    s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
    if (m[5]) {
        s += ":" + m[5];
        if (m[6]) {
            s += ":" + m[6];
            if (m[7])
                s += "." + m[7];
        }
    }
    if (m[8]) {
        s += " UTC";
        if (m[8] != 'Z') {
            s += m[8];
            if (m[9])
                s += ":" + m[9];
        }
    }
    return s;
}
Stream.prototype.parseInteger = function(start, end) {
    //TODO support negative numbers
    var len = end - start;
    if (len > 4) {
        len <<= 3;
        var s = this.get(start);
        if (s == 0)
            len -= 8;
        else
            while (s < 128) {
                s <<= 1;
                --len;
            }
        return "(" + len + " bit)";
    }
    var n = 0;
    for (var i = start; i < end; ++i)
        n = (n << 8) | this.get(i);
    return n;
}
Stream.prototype.parseBitString = function(start, end) {
    var unusedBit = this.get(start);
    var lenBit = ((end - start - 1) << 3) - unusedBit;
    var s  = "(" + lenBit + " bit)";
    if (lenBit <= 20) {
        var skip = unusedBit;
        s += " ";
        for (var i = end - 1; i > start; --i) {
            var b = this.get(i);
            for (var j = skip; j < 8; ++j)
                s += (b >> j) & 1 ? "1" : "0";
            skip = 0;
        }
    }
    return s;
}
Stream.prototype.parseOctetString = function(start, end) {
    var len = end - start;
    var s = "(" + len + " byte) ";
    if (len > 20)
        end = start + 20;
    for (var i = start; i < end; ++i)
        s += this.hexByte(this.get(i));
    if (len > 20)
        s += String.fromCharCode(8230); // ellipsis
    return s;
}
Stream.prototype.parseOID = function(start, end) {
    var s, n = 0, bits = 0;
    for (var i = start; i < end; ++i) {
        var v = this.get(i);
        n = (n << 7) | (v & 0x7F);
        bits += 7;
        if (!(v & 0x80)) { // finished
            if (s == undefined)
                s = parseInt(n / 40) + "." + (n % 40);
            else
                s += "." + ((bits >= 31) ? "bigint" : n);
            n = bits = 0;
        }
        s += String.fromCharCode();
    }
    return s;
}

function ASN1(stream, header, length, tag, sub) {
    this.stream = stream;
    this.header = header;
    this.length = length;
    this.tag = tag;
    this.sub = sub;
}
ASN1.prototype.typeName = function() {
    if (this.tag == undefined)
        return "unknown";
    var tagClass = this.tag >> 6;
    var tagConstructed = (this.tag >> 5) & 1;
    var tagNumber = this.tag & 0x1F;
    switch (tagClass) {
    case 0: // universal
        switch (tagNumber) {
        case 0x00: return "EOC";
        case 0x01: return "BOOLEAN";
        case 0x02: return "INTEGER";
        case 0x03: return "BIT_STRING";
        case 0x04: return "OCTET_STRING";
        case 0x05: return "NULL";
        case 0x06: return "OBJECT_IDENTIFIER";
        case 0x07: return "ObjectDescriptor";
        case 0x08: return "EXTERNAL";
        case 0x09: return "REAL";
        case 0x0A: return "ENUMERATED";
        case 0x0B: return "EMBEDDED_PDV";
        case 0x0C: return "UTF8String";
        case 0x10: return "SEQUENCE";
        case 0x11: return "SET";
        case 0x12: return "NumericString";
        case 0x13: return "PrintableString"; // ASCII subset
        case 0x14: return "TeletexString"; // aka T61String
        case 0x15: return "VideotexString";
        case 0x16: return "IA5String"; // ASCII
        case 0x17: return "UTCTime";
        case 0x18: return "GeneralizedTime";
        case 0x19: return "GraphicString";
        case 0x1A: return "VisibleString"; // ASCII subset
        case 0x1B: return "GeneralString";
        case 0x1C: return "UniversalString";
        case 0x1E: return "BMPString";
        default: return "Universal_" + tagNumber.toString(16);
        }
    case 1: return "Application_" + tagNumber.toString(16);
    case 2: return "[" + tagNumber + "]"; // Context
    case 3: return "Private_" + tagNumber.toString(16);
    }
}
ASN1.prototype.content = function() {
    if (this.tag == undefined)
        return null;
    var tagClass = this.tag >> 6;
    if (tagClass != 0) // universal
        return (this.sub == null) ? null : "(" + this.sub.length + ")";
    var tagNumber = this.tag & 0x1F;
    var content = this.posContent();
    var len = Math.abs(this.length);
    switch (tagNumber) {
    case 0x01: // BOOLEAN
        return (this.stream.get(content) == 0) ? "false" : "true";
    case 0x02: // INTEGER
        return this.stream.parseInteger(content, content + len);
    case 0x03: // BIT_STRING
        return this.sub ? "(" + this.sub.length + " elem)" :
            this.stream.parseBitString(content, content + len)
    case 0x04: // OCTET_STRING
        return this.sub ? "(" + this.sub.length + " elem)" :
            this.stream.parseOctetString(content, content + len)
    //case 0x05: // NULL
    case 0x06: // OBJECT_IDENTIFIER
        return this.stream.parseOID(content, content + len);
    //case 0x07: // ObjectDescriptor
    //case 0x08: // EXTERNAL
    //case 0x09: // REAL
    //case 0x0A: // ENUMERATED
    //case 0x0B: // EMBEDDED_PDV
    case 0x10: // SEQUENCE
    case 0x11: // SET
        return "(" + this.sub.length + " elem)";
    case 0x0C: // UTF8String
        return this.stream.parseStringUTF(content, content + len);
    case 0x12: // NumericString
    case 0x13: // PrintableString
    case 0x14: // TeletexString
    case 0x15: // VideotexString
    case 0x16: // IA5String
    //case 0x19: // GraphicString
    case 0x1A: // VisibleString
    //case 0x1B: // GeneralString
    //case 0x1C: // UniversalString
    //case 0x1E: // BMPString
        return this.stream.parseStringISO(content, content + len);
    case 0x17: // UTCTime
    case 0x18: // GeneralizedTime
        return this.stream.parseTime(content, content + len);
    }
    return null;
}
ASN1.prototype.toString = function() {
    return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub == null) ? 'null' : this.sub.length) + "]";
}
ASN1.prototype.print = function(indent) {
    if (indent == undefined) indent = '';
    document.writeln(indent + this);
    if (this.sub != null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            this.sub[i].print(indent);
    }
}
ASN1.prototype.toPrettyString = function(indent) {
    if (indent == undefined) indent = '';
    var s = indent + this.typeName() + " @" + this.stream.pos;
    if (this.length >= 0)
        s += "+";
    s += this.length;
    if (this.tag & 0x20)
        s += " (constructed)";
    else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub != null))
        s += " (encapsulates)";
    s += "\n";
    if (this.sub != null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            s += this.sub[i].toPrettyString(indent);
    }
    return s;
}
ASN1.prototype.posStart = function() {
    return this.stream.pos;
}
ASN1.prototype.posContent = function() {
    return this.stream.pos + this.header;
}
ASN1.prototype.posEnd = function() {
    return this.stream.pos + this.header + Math.abs(this.length);
}
ASN1.decodeLength = function(stream) {
    var buf = stream.get();
    var len = buf & 0x7F;
    if (len == buf)
        return len;
    if (len > 3)
        throw "Length over 24 bits not supported at position " + (stream.pos - 1);
    if (len == 0)
        return -1; // undefined
    buf = 0;
    for (var i = 0; i < len; ++i)
        buf = (buf << 8) | stream.get();
    return buf;
}
ASN1.hasContent = function(tag, len, stream) {
    if (tag & 0x20) // constructed
        return true;
    if ((tag < 0x03) || (tag > 0x04))
        return false;
    var p = new Stream(stream);
    if (tag == 0x03) p.get(); // BitString unused bits, must be in [0, 7]
    var subTag = p.get();
    if ((subTag >> 6) & 0x01) // not (universal or context)
        return false;
    try {
        var subLength = ASN1.decodeLength(p);
        return ((p.pos - stream.pos) + subLength == len);
    } catch (exception) {
        return false;
    }
}
ASN1.decode = function(stream) {
    if (!(stream instanceof Stream))
        stream = new Stream(stream, 0);
    var streamStart = new Stream(stream);
    var tag = stream.get();
    var len = ASN1.decodeLength(stream);
    var header = stream.pos - streamStart.pos;
    var sub = null;
    if (ASN1.hasContent(tag, len, stream)) {
        // it has content, so we decode it
        var start = stream.pos;
        if (tag == 0x03) stream.get(); // skip BitString unused bits, must be in [0, 7]
        sub = [];
        if (len >= 0) {
            // definite length
            var end = start + len;
            while (stream.pos < end)
                sub[sub.length] = ASN1.decode(stream);
            if (stream.pos != end)
                throw "Content size is not correct for container starting at offset " + start;
        } else {
            // undefined length
            try {
                for (;;) {
                    var s = ASN1.decode(stream);
                    if (s.tag == 0)
                        break;
                    sub[sub.length] = s;
                }
                len = start - stream.pos;
            } catch (e) {
                throw "Exception while decoding undefined length content: " + e;
            }
        }
    } else
        stream.pos += len; // skip content
    return new ASN1(streamStart, header, len, tag, sub);
}

var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64padchar="=";

function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  for(i = 0; i+3 <= h.length; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  while((ret.length & 3) > 0) ret += b64padchar;
  return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
  var ret = "";
  var i;
  var k = 0; // b64 state, 0-3
  var slop;
  var v;
  for(i = 0; i < s.length; ++i) {
    if(s.charAt(i) == b64padchar) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}

// convert a base64 string to a byte/number array
function b64toBA(s) {
  //piggyback on b64tohex for now, optimize later
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}

// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this.DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    throw new Error("Message too long for RSA");
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var randomByte = 0;
  var random = 0;
  var shift = 0;
  while(n > 2) { // random non-zero pad
    if (shift == 0) {
      random = sjcl.random.randomWords(1, 0)[0];
    }

    randomByte = (random >> shift) & 0xff;
    shift = (shift + 8) % 32;
    if (randomByte != 0) {
      ba[--n] = randomByte;
    }
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// "empty" RSA key constructor
function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}

// Set the public key fields N and e from hex strings
function RSASetPublic(N,E) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    throw new Error("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

"use strict";
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape */

/** @namespace The Stanford Javascript Crypto Library, top-level namespace. */
var sjcl = {
  /** @namespace Symmetric ciphers. */
  cipher: {},

  /** @namespace Hash functions.  Right now only SHA256 is implemented. */
  hash: {},

  /** @namespace Key exchange functions.  Right now only SRP is implemented. */
  keyexchange: {},
  
  /** @namespace Block cipher modes of operation. */
  mode: {},

  /** @namespace Miscellaneous.  HMAC and PBKDF2. */
  misc: {},
  
  /**
   * @namespace Bit array encoders and decoders.
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
  codec: {},
  
  /** @namespace Exceptions. */
  exception: {
    /** @class Ciphertext is corrupt. */
    corrupt: function(message) {
      this.toString = function() { return "CORRUPT: "+this.message; };
      this.message = message;
    },
    
    /** @class Invalid parameter. */
    invalid: function(message) {
      this.toString = function() { return "INVALID: "+this.message; };
      this.message = message;
    },
    
    /** @class Bug or missing feature in SJCL. */
    bug: function(message) {
      this.toString = function() { return "BUG: "+this.message; };
      this.message = message;
    },

    /** @class Something isn't ready. */
    notReady: function(message) {
      this.toString = function() { return "NOT READY: "+this.message; };
      this.message = message;
    }
  }
};

if(typeof module != 'undefined' && module.exports){
  module.exports = sjcl;
}

/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
sjcl.cipher.aes = function (key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }
  
  var i, j, tmp,
    encKey, decKey,
    sbox = this._tables[0][4], decTable = this._tables[1],
    keyLen = key.length, rcon = 1;
  
  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }
  
  this._key = [encKey = key.slice(0), decKey = []];
  
  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i-1];
    
    // apply sbox
    if (i%keyLen === 0 || (keyLen === 8 && i%keyLen === 4)) {
      tmp = sbox[tmp>>>24]<<24 ^ sbox[tmp>>16&255]<<16 ^ sbox[tmp>>8&255]<<8 ^ sbox[tmp&255];
      
      // shift rows and add rcon
      if (i%keyLen === 0) {
        tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
        rcon = rcon<<1 ^ (rcon>>7)*283;
      }
    }
    
    encKey[i] = encKey[i-keyLen] ^ tmp;
  }
  
  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j&3 ? i : i - 4];
    if (i<=4 || j<4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp>>>24      ]] ^
                  decTable[1][sbox[tmp>>16  & 255]] ^
                  decTable[2][sbox[tmp>>8   & 255]] ^
                  decTable[3][sbox[tmp      & 255]];
    }
  }
};

sjcl.cipher.aes.prototype = {
  // public
  /* Something like this might appear here eventually
  name: "AES",
  blockSize: 4,
  keySizes: [4,6,8],
  */
  
  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt:function (data) { return this._crypt(data,0); },
  
  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt:function (data) { return this._crypt(data,1); },
  
  /**
   * The expanded S-box and inverse S-box tables.  These will be computed
   * on the client so that we don't have to send them down the wire.
   *
   * There are two tables, _tables[0] is for encryption and
   * _tables[1] is for decryption.
   *
   * The first 4 sub-tables are the expanded S-box with MixColumns.  The
   * last (_tables[01][4]) is the S-box itself.
   *
   * @private
   */
  _tables: [[[],[],[],[],[]],[[],[],[],[],[]]],

  /**
   * Expand the S-box tables.
   *
   * @private
   */
  _precompute: function () {
   var encTable = this._tables[0], decTable = this._tables[1],
       sbox = encTable[4], sboxInv = decTable[4],
       i, x, xInv, d=[], th=[], x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
   for (i = 0; i < 256; i++) {
     th[( d[i] = i<<1 ^ (i>>7)*283 )^i]=i;
   }
   
   for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
     // Compute sbox
     s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
     s = s>>8 ^ s&255 ^ 99;
     sbox[x] = s;
     sboxInv[s] = x;
     
     // Compute MixColumns
     x8 = d[x4 = d[x2 = d[x]]];
     tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
     tEnc = d[s]*0x101 ^ s*0x1010100;
     
     for (i = 0; i < 4; i++) {
       encTable[i][x] = tEnc = tEnc<<24 ^ tEnc>>>8;
       decTable[i][s] = tDec = tDec<<24 ^ tDec>>>8;
     }
   }
   
   // Compactify.  Considerable speedup on Firefox.
   for (i = 0; i < 5; i++) {
     encTable[i] = encTable[i].slice(0);
     decTable[i] = decTable[i].slice(0);
   }
  },
  
  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt:function (input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }
    
    var key = this._key[dir],
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0]           ^ key[0],
        b = input[dir ? 3 : 1] ^ key[1],
        c = input[2]           ^ key[2],
        d = input[dir ? 1 : 3] ^ key[3],
        a2, b2, c2,
        
        nInnerRounds = key.length/4 - 2,
        i,
        kIndex = 4,
        out = [0,0,0,0],
        table = this._tables[dir],
        
        // load up the tables
        t0    = table[0],
        t1    = table[1],
        t2    = table[2],
        t3    = table[3],
        sbox  = table[4];
 
    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a>>>24] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b>>>24] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c>>>24] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d  = t0[d>>>24] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a=a2; b=b2; c=c2;
    }
        
    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3&-i : i] =
        sbox[a>>>24      ]<<24 ^ 
        sbox[b>>16  & 255]<<16 ^
        sbox[c>>8   & 255]<<8  ^
        sbox[d      & 255]     ^
        key[kIndex++];
      a2=a; a=b; b=c; c=d; d=a2;
    }
    
    return out;
  }
};


/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Arrays of bits, encoded as arrays of Numbers.
 *
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = {
  /**
   * Array slices in units of bits.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
  bitSlice: function (a, bstart, bend) {
    a = sjcl.bitArray._shiftRight(a.slice(bstart/32), 32 - (bstart & 31)).slice(1);
    return (bend === undefined) ? a : sjcl.bitArray.clamp(a, bend-bstart);
  },

  /**
   * Extract a number packed into a bit array.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} length The length of the number to extract.
   * @return {Number} The requested slice.
   */
  extract: function(a, bstart, blength) {
    // FIXME: this Math.floor is not necessary at all, but for some reason
    // seems to suppress a bug in the Chromium JIT.
    var x, sh = Math.floor((-bstart-blength) & 31);
    if ((bstart + blength - 1 ^ bstart) & -32) {
      // it crosses a boundary
      x = (a[bstart/32|0] << (32 - sh)) ^ (a[bstart/32+1|0] >>> sh);
    } else {
      // within a single word
      x = a[bstart/32|0] >>> sh;
    }
    return x & ((1<<blength) - 1);
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
  concat: function (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }
    
    var out, i, last = a1[a1.length-1], shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(a2, shift, last|0, a1.slice(0,a1.length-1));
    }
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
  bitLength: function (a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
  clamp: function (a, len) {
    if (a.length * 32 < len) { return a; }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l-1] = sjcl.bitArray.partial(len, a[l-1] & 0x80000000 >> (len-1), 1);
    }
    return a;
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
  partial: function (len, x, _end) {
    if (len === 32) { return x; }
    return (_end ? x|0 : x << (32-len)) + len * 0x10000000000;
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
  getPartial: function (x) {
    return Math.round(x/0x10000000000) || 32;
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0, i;
    for (i=0; i<a.length; i++) {
      x |= a[i]^b[i];
    }
    return (x === 0);
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
  _shiftRight: function (a, shift, carry, out) {
    var i, last2=0, shift2;
    if (out === undefined) { out = []; }
    
    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }
    
    for (i=0; i<a.length; i++) {
      out.push(carry | a[i]>>>shift);
      carry = a[i] << (32-shift);
    }
    last2 = a.length ? a[a.length-1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(sjcl.bitArray.partial(shift+shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(),1));
    return out;
  },
  
  /** xor a block of 4 words together.
   * @private
   */
  _xor4: function(x,y) {
    return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Hexadecimal */
sjcl.codec.hex = {
  /** Convert from a bitArray to a hex string. */
  fromBits: function (arr) {
    var out = "", i, x;
    for (i=0; i<arr.length; i++) {
      out += ((arr[i]|0)+0xF00000000000).toString(16).substr(4);
    }
    return out.substr(0, sjcl.bitArray.bitLength(arr)/4);//.replace(/(.{8})/g, "$1 ");
  },
  /** Convert from a hex string to a bitArray. */
  toBits: function (str) {
    var i, out=[], len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str = str + "00000000";
    for (i=0; i<str.length; i+=8) {
      out.push(parseInt(str.substr(i,8),16)^0);
    }
    return sjcl.bitArray.clamp(out, len*4);
  }
};


/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
/** @namespace UTF-8 strings */
sjcl.codec.utf8String = {
  /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },
  
  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function (str) {
    str = unescape(encodeURIComponent(str));
    var out = [], i, tmp=0;
    for (i=0; i<str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Base64 encoding/decoding */
sjcl.codec.base64 = {
  /** The base64 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  
  /** Convert from a bitArray to a base64 string. */
  fromBits: function (arr, _noEquals, _url) {
    var out = "", i, bits=0, c = sjcl.codec.base64._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6-bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while ((out.length & 3) && !_noEquals) { out += "="; }
    return out;
  },
  
  /** Convert from a base64 string to a bitArray */
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g,'');
    var out = [], i, bits=0, c = sjcl.codec.base64._chars, ta=0, x;
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ x>>>bits);
        ta  = x << (32-bits);
      } else {
        bits += 6;
        ta ^= x << (32-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr,1,1); },
  toBits: function (str) { return sjcl.codec.base64.toBits(str,1); }
};

/** @fileOverview CBC mode implementation
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace
 * Dangerous: CBC mode with PKCS#5 padding.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
if (sjcl.beware === undefined) {
  sjcl.beware = {};
}
sjcl.beware["CBC mode is dangerous because it doesn't protect message integrity."
] = function() {
  sjcl.mode.cbc = {
    /** The name of the mode.
     * @constant
     */
    name: "cbc",
    
    /** Encrypt in CBC mode with PKCS#5 padding.
     * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data.  Must be empty.
     * @return The encrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     */
    encrypt: function(prp, plaintext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("cbc can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      }
      var i,
          w = sjcl.bitArray,
          xor = w._xor4,
          bl = w.bitLength(plaintext),
          bp = 0,
          output = [];

      if (bl&7) {
        throw new sjcl.exception.invalid("pkcs#5 padding only works for multiples of a byte");
      }
    
      for (i=0; bp+128 <= bl; i+=4, bp+=128) {
        /* Encrypt a non-final block */
        iv = prp.encrypt(xor(iv, plaintext.slice(i,i+4)));
        output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
      }
      
      /* Construct the pad. */
      bl = (16 - ((bl >> 3) & 15)) * 0x1010101;

      /* Pad and encrypt. */
      iv = prp.encrypt(xor(iv,w.concat(plaintext,[bl,bl,bl,bl]).slice(i,i+4)));
      output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
      return output;
    },
    
    /** Decrypt in CBC mode.
     * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
     * @param {bitArray} ciphertext The ciphertext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data.  It must be empty.
     * @return The decrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     * @throws {sjcl.exception.corrupt} if if the message is corrupt.
     */
    decrypt: function(prp, ciphertext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("cbc can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      }
      if ((sjcl.bitArray.bitLength(ciphertext) & 127) || !ciphertext.length) {
        throw new sjcl.exception.corrupt("cbc ciphertext must be a positive multiple of the block size");
      }
      var i,
          w = sjcl.bitArray,
          xor = w._xor4,
          bi, bo,
          output = [];
          
      adata = adata || [];
    
      for (i=0; i<ciphertext.length; i+=4) {
        bi = ciphertext.slice(i,i+4);
        bo = xor(iv,prp.decrypt(bi));
        output.splice(i,0,bo[0],bo[1],bo[2],bo[3]);
        iv = bi;
      }

      /* check and remove the pad */
      bi = output[i-1] & 255;
      if (bi == 0 || bi > 16) {
        throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
      }
      bo = bi * 0x1010101;
      if (!w.equal(w.bitSlice([bo,bo,bo,bo], 0, bi*8),
                   w.bitSlice(output, output.length*32 - bi*8, output.length*32))) {
        throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
      }

      return w.bitSlice(output, 0, output.length*32 - bi*8);
    }
  };
};

/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [hash=sjcl.hash.sha256] The hash function to use.
 */
sjcl.misc.hmac = function (key, Hash) {
  this._hash = Hash = Hash || sjcl.hash.sha256;
  var exKey = [[],[]], i,
      bs = Hash.prototype.blockSize / 32;
  this._baseHash = [new Hash(), new Hash()];

  if (key.length > bs) {
    key = Hash.hash(key);
  }
  
  for (i=0; i<bs; i++) {
    exKey[0][i] = key[i]^0x36363636;
    exKey[1][i] = key[i]^0x5C5C5C5C;
  }
  
  this._baseHash[0].update(exKey[0]);
  this._baseHash[1].update(exKey[1]);
};

/** HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 * @param {Codec} [encoding] the encoding function to use.
 */
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (data, encoding) {
  var w = new (this._hash)(this._baseHash[0]).update(data, encoding).finalize();
  return new (this._hash)(this._baseHash[1]).update(w).finalize();
};


/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 * @class Secure Hash Algorithm, 256 bits.
 */
sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) { this._precompute(); }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
sjcl.hash.sha256.hash = function (data) {
  return (new sjcl.hash.sha256()).update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
  blockSize: 512,
   
  /**
   * Reset the hash state.
   * @return this
   */
  reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
        ol = this._length,
        nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = 512+ol & -512; i <= nl; i+= 512) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 16 big-endian words.
   */
  finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    
    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    return h;
  },

  /**
   * The SHA-256 initialization vector, to be precomputed.
   * @private
   */
  _init:[],
  /*
  _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */
  
  /**
   * The SHA-256 hash key, to be precomputed.
   * @private
   */
  _key:[],
  /*
  _key:
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
  */


  /**
   * Function to precompute _init and _key.
   * @private
   */
  _precompute: function () {
    var i = 0, prime = 2, factor;

    function frac(x) { return (x-Math.floor(x)) * 0x100000000 | 0; }

    outer: for (; i<64; prime++) {
      for (factor=2; factor*factor <= prime; factor++) {
        if (prime % factor === 0) {
          // not a prime
          continue outer;
        }
      }
      
      if (i<8) {
        this._init[i] = frac(Math.pow(prime, 1/2));
      }
      this._key[i] = frac(Math.pow(prime, 1/3));
      i++;
    }
  },
  
  /**
   * Perform one cycle of SHA-256.
   * @param {bitArray} words one block of words.
   * @private
   */
  _block:function (words) {  
    var i, tmp, a, b,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
      h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    /* Rationale for placement of |0 :
     * If a value can overflow is original 32 bits by a factor of more than a few
     * million (2^23 ish), there is a possibility that it might overflow the
     * 53-bit mantissa and lose precision.
     *
     * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
     * propagates around the loop, and on the hash state h[].  I don't believe
     * that the clamps on h4 and on h0 are strictly necessary, but it's close
     * (for h4 anyway), and better safe than sorry.
     *
     * The clamps on h[] are necessary for the output to be correct even in the
     * common case and for short inputs.
     */
    for (i=0; i<64; i++) {
      // load up the input word for this round
      if (i<16) {
        tmp = w[i];
      } else {
        a   = w[(i+1 ) & 15];
        b   = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7  ^ a>>>18 ^ a>>>3  ^ a<<25 ^ a<<14) + 
                         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
                         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) +  (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp +  ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0]+h0 | 0;
    h[1] = h[1]+h1 | 0;
    h[2] = h[2]+h2 | 0;
    h[3] = h[3]+h3 | 0;
    h[4] = h[4]+h4 | 0;
    h[5] = h[5]+h5 | 0;
    h[6] = h[6]+h6 | 0;
    h[7] = h[7]+h7 | 0;
  }
};



/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Random number generator
 *
 * @description
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 */
sjcl.random = {
  /** Generate several random words, and return them in an array
   * @param {Number} nwords The number of words to generate.
   */
  randomWords: function (nwords, paranoia) {
    var out = [], i, readiness = this.isReady(paranoia), g;
  
    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }
  
    for (i=0; i<nwords; i+= 4) {
      if ((i+1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }
   
      g = this._gen4words();
      out.push(g[0],g[1],g[2],g[3]);
    }
    this._gate();
  
    return out.slice(0,nwords);
  },
  
  setDefaultParanoia: function (paranoia) {
    this._defaultParanoia = paranoia;
  },
  
  /**
   * Add entropy to the pools.
   * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
   * @param {Number} estimatedEntropy The estimated entropy of data, in bits
   * @param {String} source The source of the entropy, eg "mouse"
   */
  addEntropy: function (data, estimatedEntropy, source) {
    source = source || "user";
  
    var id,
      i, tmp,
      t = (new Date()).valueOf(),
      robin = this._robins[source],
      oldReady = this.isReady(), err = 0;
      
    id = this._collectorIds[source];
    if (id === undefined) { id = this._collectorIds[source] = this._collectorIdNext ++; }
      
    if (robin === undefined) { robin = this._robins[source] = 0; }
    this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;
  
    switch(typeof(data)) {
      
    case "number":
      if (estimatedEntropy === undefined) {
        estimatedEntropy = 1;
      }
      this._pools[robin].update([id,this._eventId++,1,estimatedEntropy,t,1,data|0]);
      break;
      
    case "object":
      var objName = Object.prototype.toString.call(data);
      if (objName === "[object Uint32Array]") {
        tmp = [];
        for (i = 0; i < data.length; i++) {
          tmp.push(data[i]);
        }
        data = tmp;
      } else {
        if (objName !== "[object Array]") {
          err = 1;
        }
        for (i=0; i<data.length && !err; i++) {
          if (typeof(data[i]) != "number") {
            err = 1;
          }
        }
      }
      if (!err) {
        if (estimatedEntropy === undefined) {
          /* horrible entropy estimator */
          estimatedEntropy = 0;
          for (i=0; i<data.length; i++) {
            tmp= data[i];
            while (tmp>0) {
              estimatedEntropy++;
              tmp = tmp >>> 1;
            }
          }
        }
        this._pools[robin].update([id,this._eventId++,2,estimatedEntropy,t,data.length].concat(data));
      }
      break;
      
    case "string":
      if (estimatedEntropy === undefined) {
       /* English text has just over 1 bit per character of entropy.
        * But this might be HTML or something, and have far less
        * entropy than English...  Oh well, let's just say one bit.
        */
       estimatedEntropy = data.length;
      }
      this._pools[robin].update([id,this._eventId++,3,estimatedEntropy,t,data.length]);
      this._pools[robin].update(data);
      break;
      
    default:
      err=1;
    }
    if (err) {
      throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
    }
  
    /* record the new strength */
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;
  
    /* fire off events */
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },
  
  /** Is the generator ready? */
  isReady: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ (paranoia !== undefined) ? paranoia : this._defaultParanoia ];
  
    if (this._strength && this._strength >= entropyRequired) {
      return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
        this._REQUIRES_RESEED | this._READY :
        this._READY;
    } else {
      return (this._poolStrength >= entropyRequired) ?
        this._REQUIRES_RESEED | this._NOT_READY :
        this._NOT_READY;
    }
  },
  
  /** Get the generator's progress toward readiness, as a fraction */
  getProgress: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._defaultParanoia ];
  
    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return (this._poolStrength > entropyRequired) ?
        1.0 :
        this._poolStrength / entropyRequired;
    }
  },
  
  /** start the built-in entropy collectors */
  startCollectors: function () {
    if (this._collectorsStarted) { return; }
  
    if (window.addEventListener) {
      window.addEventListener("load", this._loadTimeCollector, false);
      window.addEventListener("mousemove", this._mouseCollector, false);
    } else if (document.attachEvent) {
      document.attachEvent("onload", this._loadTimeCollector);
      document.attachEvent("onmousemove", this._mouseCollector);
    }
    else {
      throw new sjcl.exception.bug("can't attach event");
    }
  
    this._collectorsStarted = true;
  },
  
  /** stop the built-in entropy collectors */
  stopCollectors: function () {
    if (!this._collectorsStarted) { return; }
  
    if (window.removeEventListener) {
      window.removeEventListener("load", this._loadTimeCollector, false);
      window.removeEventListener("mousemove", this._mouseCollector, false);
    } else if (window.detachEvent) {
      window.detachEvent("onload", this._loadTimeCollector);
      window.detachEvent("onmousemove", this._mouseCollector);
    }
    this._collectorsStarted = false;
  },
  
  /* use a cookie to store entropy.
  useCookie: function (all_cookies) {
      throw new sjcl.exception.bug("random: useCookie is unimplemented");
  },*/
  
  /** add an event listener for progress or seeded-ness. */
  addEventListener: function (name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },
  
  /** remove an event listener for progress or seeded-ness */
  removeEventListener: function (name, cb) {
    var i, j, cbs=this._callbacks[name], jsTemp=[];
  
    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */
  
    for (j in cbs) {
	if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }
  
    for (i=0; i<jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },
  
  /* private */
  _pools                   : [new sjcl.hash.sha256()],
  _poolEntropy             : [0],
  _reseedCount             : 0,
  _robins                  : {},
  _eventId                 : 0,
  
  _collectorIds            : {},
  _collectorIdNext         : 0,
  
  _strength                : 0,
  _poolStrength            : 0,
  _nextReseed              : 0,
  _key                     : [0,0,0,0,0,0,0,0],
  _counter                 : [0,0,0,0],
  _cipher                  : undefined,
  _defaultParanoia         : 6,
  
  /* event listener stuff */
  _collectorsStarted       : false,
  _callbacks               : {progress: {}, seeded: {}},
  _callbackI               : 0,
  
  /* constants */
  _NOT_READY               : 0,
  _READY                   : 1,
  _REQUIRES_RESEED         : 2,

  _MAX_WORDS_PER_BURST     : 65536,
  _PARANOIA_LEVELS         : [0,48,64,96,128,192,256,384,512,768,1024],
  _MILLISECONDS_PER_RESEED : 30000,
  _BITS_PER_RESEED         : 80,
  
  /** Generate 4 random words, no reseed, no gate.
   * @private
   */
  _gen4words: function () {
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
    return this._cipher.encrypt(this._counter);
  },
  
  /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
   * @private
   */
  _gate: function () {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },
  
  /** Reseed the generator with the given words
   * @private
   */
  _reseed: function (seedWords) {
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
  },
  
  /** reseed the data from the entropy pools
   * @param full If set, use all the entropy pools in the reseed.
   */
  _reseedFromPools: function (full) {
    var reseedData = [], strength = 0, i;
  
    this._nextReseed = reseedData[0] =
      (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
    
    for (i=0; i<16; i++) {
      /* On some browsers, this is cryptographically random.  So we might
       * as well toss it in the pot and stir...
       */
      reseedData.push(Math.random()*0x100000000|0);
    }
    
    for (i=0; i<this._pools.length; i++) {
     reseedData = reseedData.concat(this._pools[i].finalize());
     strength += this._poolEntropy[i];
     this._poolEntropy[i] = 0;
   
     if (!full && (this._reseedCount & (1<<i))) { break; }
    }
  
    /* if we used the last pool, push a new one onto the stack */
    if (this._reseedCount >= 1 << this._pools.length) {
     this._pools.push(new sjcl.hash.sha256());
     this._poolEntropy.push(0);
    }
  
    /* how strong was this reseed? */
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }
  
    this._reseedCount ++;
    this._reseed(reseedData);
  },
  
  _mouseCollector: function (ev) {
    var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
    sjcl.random.addEntropy([x,y], 2, "mouse");
  },
  
  _loadTimeCollector: function (ev) {
    sjcl.random.addEntropy((new Date()).valueOf(), 2, "loadtime");
  },
  
  _fireEvent: function (name, arg) {
    var j, cbs=sjcl.random._callbacks[name], cbsTemp=[];
    /* TODO: there is a race condition between removing collectors and firing them */ 

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */
  
    for (j in cbs) {
     if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
     }
    }
  
    for (j=0; j<cbsTemp.length; j++) {
     cbsTemp[j](arg);
    }
  }
};

(function(){
  try {
    // get cryptographically strong entropy in Webkit
    var ab = new Uint32Array(32);
    crypto.getRandomValues(ab);
    sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
  } catch (e) {
    // no getRandomValues :-(
  }
})();

(function () {
  for (var key in sjcl.beware) {
    if (sjcl.beware.hasOwnProperty(key)) {
      sjcl.beware[key]();
    }
  }
})();

var Braintree = {
  sjcl: sjcl,
  version: "1.3.10"
};

Braintree.generateAesKey = function () {
  return {
    key: sjcl.random.randomWords(8, 0),
    encrypt: function (plainText) {
      return this.encryptWithIv(plainText, sjcl.random.randomWords(4, 0));
    },
    encryptWithIv: function (plaintext, iv) {
      var aes = new sjcl.cipher.aes(this.key),
          plaintextBits = sjcl.codec.utf8String.toBits(plaintext),
          ciphertextBits = sjcl.mode.cbc.encrypt(aes, plaintextBits, iv),
          ciphertextAndIvBits = sjcl.bitArray.concat(iv, ciphertextBits);

      return sjcl.codec.base64.fromBits(ciphertextAndIvBits);
    }
  };
};

Braintree.create = function (publicKey) {
  return new Braintree.EncryptionClient(publicKey);
};

Braintree.EncryptionClient = function (publicKey) {
  var self = this,
      hiddenFields = [];

  self.publicKey = publicKey;
  self.version = Braintree.version;

  var createElement = function (tagName, attrs) {
    var element, attr, value;

    element = document.createElement(tagName);

    for (attr in attrs) {
      if (attrs.hasOwnProperty(attr)) {
        value = attrs[attr];
        element.setAttribute(attr, value);
      }
    }

    return element;
  };

  var extractForm = function (object) {
    if (window.jQuery && object instanceof jQuery) {
      return object[0];
    } else if (object.nodeType && object.nodeType === 1) {
      return object;
    } else {
      return document.getElementById(object);
    }
  };

  var extractIntegers = function (asn1) {
    var parts = [],
        start, end, data,
        i;

    if (asn1.typeName() === "INTEGER") {
      start = asn1.posContent();
      end   = asn1.posEnd();
      data  = asn1.stream.hexDump(start, end).replace(/[ \n]/g, "");
      parts.push(data);
    }

    if (asn1.sub !== null) {
      for (i = 0; i < asn1.sub.length; i++) {
        parts = parts.concat(extractIntegers(asn1.sub[i]));
      }
    }

    return parts;
  };

  var findInputs = function (element) {
    var found = [],
        children = element.children,
        child, i;

    for (i = 0; i < children.length; i++) {
      child = children[i];

      if (child.nodeType === 1 && child.attributes["data-encrypted-name"]) {
        found.push(child);
      } else if (child.children && child.children.length > 0) {
        found = found.concat(findInputs(child));
      }
    }

    return found;
  };

  var generateRsaKey = function () {
    var asn1, exponent, parts, modulus, rawKey, rsa;

    try {
      rawKey = b64toBA(publicKey);
      asn1 = ASN1.decode(rawKey);
    } catch (e) {
      throw "Invalid encryption key. Please use the key labeled 'Client-Side Encryption Key'";
    }

    parts = extractIntegers(asn1);

    if (parts.length !== 2) {
      throw "Invalid encryption key. Please use the key labeled 'Client-Side Encryption Key'";
    }

    modulus = parts[0];
    exponent = parts[1];

    rsa = new RSAKey();
    rsa.setPublic(modulus, exponent);

    return rsa;
  };

  var generateHmacKey = function () {
    return {
      key: sjcl.random.randomWords(8, 0),
      sign: function (message) {
        var hmac = new sjcl.misc.hmac(this.key, sjcl.hash.sha256),
            signature = hmac.encrypt(message);

        return sjcl.codec.base64.fromBits(signature);
      }
    };
  };

  self.encrypt = function (plaintext) {
    var rsa = generateRsaKey(),
        aes = Braintree.generateAesKey(),
        hmac = generateHmacKey(),
        ciphertext = aes.encrypt(plaintext),
        signature = hmac.sign(sjcl.codec.base64.toBits(ciphertext)),
        combinedKey = sjcl.bitArray.concat(aes.key, hmac.key),
        encodedKey = sjcl.codec.base64.fromBits(combinedKey),
        hexEncryptedKey = rsa.encrypt(encodedKey),
        prefix = "$bt4|javascript_" + self.version.replace(/\./g, "_") + "$",
        encryptedKey = null;

    if(hexEncryptedKey) {
      encryptedKey = hex2b64(hexEncryptedKey);
    }

    return prefix + encryptedKey + "$" + ciphertext + "$" + signature;
  };

  self.encryptForm = function (form) {
    var element, encryptedValue,
        fieldName, hiddenField,
        i, inputs;

    form = extractForm(form);
    inputs = findInputs(form);

    while (hiddenFields.length > 0) {
      try {
        form.removeChild(hiddenFields[0]);
      } catch (err) {}
      hiddenFields.splice(0, 1);
    }

    for (i = 0; i < inputs.length; i++) {
      element = inputs[i];
      fieldName = element.getAttribute("data-encrypted-name");
      encryptedValue = self.encrypt(element.value);
      element.removeAttribute("name");
      hiddenField = createElement("input", {
        value: encryptedValue,
        type: "hidden",
        name: fieldName
      });
      hiddenFields.push(hiddenField);
      form.appendChild(hiddenField);
    }
  };

  self.onSubmitEncryptForm = function (form, callback) {
    var wrappedCallback;

    form = extractForm(form);

    wrappedCallback = function (e) {
      self.encryptForm(form);
      return (!!callback) ? callback(e) : e;
    };

    if (window.jQuery) {
      window.jQuery(form).submit(wrappedCallback);
    } else if (form.addEventListener) {
      form.addEventListener("submit", wrappedCallback, false);
    } else if (form.attachEvent) {
      form.attachEvent("onsubmit", wrappedCallback);
    }
  };

  // backwards compatibility
  self.formEncrypter = {
    encryptForm: self.encryptForm,
    extractForm: extractForm,
    onSubmitEncryptForm: self.onSubmitEncryptForm
  };

  sjcl.random.startCollectors();
};

window.Braintree = Braintree;

})();

!function(e){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=e();else if("function"==typeof define&&define.amd)define([],e);else{var f;"undefined"!=typeof window?f=window:"undefined"!=typeof global?f=global:"undefined"!=typeof self&&(f=self),f.braintree=e()}}(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function (global){
'use strict';
/* eslint no-console: 0 */

var VERSION = "2.8.0-hosted-fields-beta.17";
var api = require('braintree-api');
var paypal = require('braintree-paypal');
var dropin = require('braintree-dropin');
var hostedFields = require('hosted-fields');
var Form = require('braintree-form');
var utils = require('braintree-utilities');
var integrations = require('./integrations');
var bus = require('braintree-bus');
var shallowClone = require('shallow-clone');
var constants = require('./constants');
var waitForDependencies = require('./lib/dependency-ready');
var sanitizePayload = require('./lib/sanitize-payload');
var listenForAnalytics = require('./lib/analytics-sender');
var _rootSuccessCallback = _noop;
var _rootReadyCallback = _noop;
var _rootErrorCallback = _fallbackError;

function _noop () {}

function _fallbackError(error) {
  if (error.type === 'CONFIGURATION' || error.type === 'IMMEDIATE') {
    throw new Error(error.message);
  } else {
    try {
      console.error(JSON.stringify(error));
    } catch (e) {}
  }
}

function setup(clientToken, integration, options) {
  if (!(integration in integrations)) {
    throw new Error(integration + ' is an unsupported integration');
  }

  if (utils.isFunction(options[constants.ROOT_SUCCESS_CALLBACK])) {
    _rootSuccessCallback = function (payload) {
      options[constants.ROOT_SUCCESS_CALLBACK](sanitizePayload(payload));
    };
  }

  if (utils.isFunction(options[constants.ROOT_ERROR_CALLBACK])) {
    _rootErrorCallback = options[constants.ROOT_ERROR_CALLBACK];
  }

  if (utils.isFunction(options[constants.ROOT_READY_CALLBACK])) {
    _rootReadyCallback = options[constants.ROOT_READY_CALLBACK];
  }

  waitForDependencies(_rootReadyCallback);
  listenForAnalytics(clientToken, integration);

  bus.on(bus.events.ERROR, _rootErrorCallback);
  bus.on(bus.events.PAYMENT_METHOD_RECEIVED, _rootSuccessCallback);
  bus.on(bus.events.WARNING, function (warning) {
    try { console.warn(warning); } catch (e) {}
  });

  api.getConfiguration(clientToken, function (err, configuration) {
    if (err) {
      bus.emit(bus.events.ERROR, {message: err.errors});
    } else {
      continueSetup(configuration, integration, options);
    }
  });
}

function continueSetup(configuration, integration, options) {
  configuration.sdkVersion = 'braintree/web/' + VERSION;
  configuration.merchantAppId = global.location.host;

  options.configuration = configuration;
  options.integration = integration;

  bus.on(bus.events.CONFIGURATION_REQUEST, function (reply) {
    var safeOptions;

    if (options.hostedFields) {
      safeOptions = shallowClone(options);

      delete safeOptions.paypal;

      reply(safeOptions);
    } else {
      reply(options);
    }
  });

  bus.emit(bus.events.ASYNC_DEPENDENCY_INITIALIZING);
  integrations[integration].initialize(configuration, options);
  bus.emit(bus.events.ASYNC_DEPENDENCY_READY);
}

module.exports = {
  api: api,
  cse: global.Braintree,
  paypal: paypal,
  dropin: dropin,
  hostedFields: {VERSION: hostedFields.VERSION},
  Form: Form,
  setup: setup,
  VERSION: VERSION
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./constants":327,"./integrations":335,"./lib/analytics-sender":337,"./lib/dependency-ready":338,"./lib/sanitize-payload":339,"braintree-api":16,"braintree-bus":39,"braintree-dropin":192,"braintree-form":202,"braintree-paypal":269,"braintree-utilities":289,"hosted-fields":291,"shallow-clone":325}],2:[function(require,module,exports){
(function (global){
'use strict';

var braintreeUtils = require('braintree-utilities');
var braintree3ds = require('braintree-3ds');
var parseClientToken = require('./parse-client-token');
var requestDriver = require('./request-driver');
var util = require('./util');
var SEPAMandate = require('./sepa-mandate');
var EuropeBankAccount = require('./europe-bank-account');
var CreditCard = require('./credit-card');
var CoinbaseAccount = require('./coinbase-account');
var PayPalAccount = require('./paypal-account');
var normalizeCreditCardFields = require('./normalize-api-fields').normalizeCreditCardFields;

function getSdkVersion(parsedClientToken) {
  var sdkVersion = parsedClientToken.sdkVersion;

  if (!sdkVersion) {
    if (global.braintree && global.braintree.VERSION) {
      sdkVersion = 'braintree/web/' + global.braintree.VERSION;
    } else {
      sdkVersion = '';
    }
  }

  return sdkVersion;
}

function Client(options) {
  var parsedClientToken, secure3d;

  this.attrs = {};

  if (options.hasOwnProperty('sharedCustomerIdentifier')) {
    this.attrs.sharedCustomerIdentifier = options.sharedCustomerIdentifier;
  }

  parsedClientToken = parseClientToken(options.clientToken);

  this.driver = options.driver || requestDriver;
  this.analyticsUrl = parsedClientToken.analytics ? parsedClientToken.analytics.url : undefined;
  this.clientApiUrl = parsedClientToken.clientApiUrl;
  this.customerId = options.customerId;
  this.challenges = parsedClientToken.challenges;
  this.integration = options.integration || '';
  this.sdkVersion = getSdkVersion(parsedClientToken);
  this.merchantAppId = parsedClientToken.merchantAppId || global.location.host;

  secure3d = braintree3ds.create(this, {
    container: options.container,
    clientToken: parsedClientToken
  });
  this.verify3DS = braintreeUtils.bind(secure3d.verify, secure3d);

  this.attrs.authorizationFingerprint = parsedClientToken.authorizationFingerprint;
  this.attrs.sharedCustomerIdentifierType = options.sharedCustomerIdentifierType;

  if (parsedClientToken.merchantAccountId) {
    this.attrs.merchantAccountId = parsedClientToken.merchantAccountId;
  }

  if (options.hasOwnProperty('timeout')) {
    this.requestTimeout = options.timeout;
  } else {
    this.requestTimeout = 60000;
  }
}

Client.prototype.getCreditCards = function (callback) {
  this.driver.get(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods']),
    this.attrs,
    function (d) {
      var i = 0;
      var len = d.paymentMethods.length;
      var creditCards = [];

      for (i; i < len; i++) {
        creditCards.push(new CreditCard(d.paymentMethods[i]));
      }

      return creditCards;
    },
    callback,
    this.requestTimeout
  );
};

Client.prototype.tokenizeCoinbase = function (attrs, callback) {
  attrs.options = { validate: false };
  this.addCoinbase(attrs, function (err, result) {
    if (err) {
      callback(err, null);
    } else if (result && result.nonce) {
      callback(err, result);
    } else {
      callback('Unable to tokenize coinbase account.', null);
    }
  });
};

Client.prototype.tokenizePayPalAccount = function (attrs, callback) {
  attrs.options = { validate: false };
  this.addPayPalAccount(attrs, function (err, result) {
    if (err) {
      callback(err, null);
    } else if (result && result.nonce) {
      callback(null, result);
    } else {
      callback('Unable to tokenize paypal account.', null);
    }
  });
};

Client.prototype.tokenizeCard = function (attrs, callback) {
  attrs.options = { validate: false };
  this.addCreditCard(attrs, function (err, result) {
    if (result && result.nonce) {
      callback(err, result.nonce, {type: result.type, details: result.details});
    } else {
      callback('Unable to tokenize card.', null);
    }
  });
};

Client.prototype.lookup3DS = function (attrs, callback) {
  var url = util.joinUrlFragments([this.clientApiUrl, 'v1/payment_methods', attrs.nonce, 'three_d_secure/lookup']);
  var mergedAttrs = util.mergeOptions(this.attrs, {amount: attrs.amount});
  this.driver.post(url, mergedAttrs, function (d) {
      return d;
    },
    callback,
    this.requestTimeout
  );
};

Client.prototype.createSEPAMandate = function (attrs, callback) {
  var mergedAttrs = util.mergeOptions(this.attrs, {sepaMandate: attrs});
  this.driver.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates.json']),
    mergedAttrs,
    function (d) { return {sepaMandate: new SEPAMandate(d.europeBankAccounts[0].sepaMandates[0]), sepaBankAccount: new EuropeBankAccount(d.europeBankAccounts[0])}; },
    callback,
    this.requestTimeout
  );
};

Client.prototype.addCoinbase = function (attrs, callback) {
  var mergedAttrs;
  delete attrs.share;

  mergedAttrs = util.mergeOptions(this.attrs, {
    coinbaseAccount: attrs,
    _meta: {
      integration: this.integration || 'custom',
      source: 'coinbase'
    }
  });

  this.driver.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/coinbase_accounts']),
    mergedAttrs,
    function (d) {
      return new CoinbaseAccount(d.coinbaseAccounts[0]);
    },
    callback,
    this.requestTimeout
  );
};

Client.prototype.addPayPalAccount = function (attrs, callback) {
  var mergedAttrs;
  delete attrs.share;

  mergedAttrs = util.mergeOptions(this.attrs, {
    paypalAccount: attrs,
    _meta: {
      integration: this.integration || 'paypal',
      source: 'paypal'
    }
  });

  this.driver.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods', 'paypal_accounts']),
    mergedAttrs,
    function (d) {
      return new PayPalAccount(d.paypalAccounts[0]);
    },
    callback,
    this.requestTimeout
  );
};

Client.prototype.addCreditCard = function (attrs, callback) {
  var mergedAttrs, creditCard;
  var share = attrs.share;
  delete attrs.share;

  creditCard = normalizeCreditCardFields(attrs);

  mergedAttrs = util.mergeOptions(this.attrs, {
    share: share,
    creditCard: creditCard,
    _meta: {
      integration: this.integration || 'custom',
      source: 'form'
    }
  });

  this.driver.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/credit_cards']),
    mergedAttrs,
    function (d) {
      return new CreditCard(d.creditCards[0]);
    },
    callback,
    this.requestTimeout
  );
};

Client.prototype.unlockCreditCard = function (creditCard, params, callback) {
  var attrs = util.mergeOptions(this.attrs, {challengeResponses: params});
  this.driver.put(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/', creditCard.nonce]),
    attrs,
    function (d) { return new CreditCard(d.paymentMethods[0]); },
    callback,
    this.requestTimeout
  );
};

Client.prototype.sendAnalyticsEvents = function (events, callback) {
  var attrs, event;
  var url = this.analyticsUrl;
  var eventObjects = [];
  events = util.isArray(events) ? events : [events];

  if (!url) {
    if (callback) {
      callback.apply(null, [null, {}]);
    }
    return;
  }

  for (event in events) {
    if (events.hasOwnProperty(event)) {
      eventObjects.push({ kind: events[event] });
    }
  }

  attrs = util.mergeOptions(this.attrs, {
    /*eslint-disable */
    braintree_library_version: this.sdkVersion,
    /*eslint-ensable */
    analytics: eventObjects,
    _meta: {
      merchantAppId: this.merchantAppId,
      platform: 'web',
      platformVersion: global.navigator.userAgent,
      integrationType: this.integration,
      sdkVersion: this.sdkVersion
    }
  });

  this.driver.post(url, attrs, function (d) { return d; }, callback, this.requestTimeout);
};

module.exports = Client;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./coinbase-account":3,"./credit-card":4,"./europe-bank-account":5,"./normalize-api-fields":9,"./parse-client-token":10,"./paypal-account":11,"./request-driver":13,"./sepa-mandate":14,"./util":15,"braintree-3ds":26,"braintree-utilities":38}],3:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'nonce',
  'type',
  'description',
  'details'
];

function CoinbaseAccount(attributes) {
  var i, attribute;

  for (i = 0; i < ATTRIBUTES.length; i++) {
    attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = CoinbaseAccount;

},{}],4:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'billingAddress',
  'branding',
  'createdAt',
  'createdAtMerchant',
  'createdAtMerchantName',
  'details',
  'isLocked',
  'lastUsedAt',
  'lastUsedAtMerchant',
  'lastUsedAtMerchantName',
  'lastUsedByCurrentMerchant',
  'nonce',
  'securityQuestions',
  'type'
];

function CreditCard(attributes) {
  var i, attribute;

  for (i = 0; i < ATTRIBUTES.length; i++) {
    attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = CreditCard;

},{}],5:[function(require,module,exports){
'use strict';

function EuropeBankAccount(attributes) {
  var allAttributes = [
    'bic',
    'maskedIBAN',
    'nonce',
    'accountHolderName'
  ];
  var attribute;
  var i = 0;

  for (i = 0; i < allAttributes.length; i++) {
    attribute = allAttributes[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = EuropeBankAccount;

},{}],6:[function(require,module,exports){
'use strict';

var parseClientToken = require('./parse-client-token');
var requestDriver = require('./request-driver');
var util = require('./util');

function getConfiguration(clientToken, callback, timeout) {
  var parsedClientToken = parseClientToken(clientToken);
  var attrs = {
    authorizationFingerprint: parsedClientToken.authorizationFingerprint
  };

  requestDriver.post(
    parsedClientToken.configUrl,
    attrs,
    function (d) {
      return util.mergeOptions(parsedClientToken, d);
    },
    callback,
    timeout
  );
}

module.exports = getConfiguration;

},{"./parse-client-token":10,"./request-driver":13,"./util":15}],7:[function(require,module,exports){
'use strict';

var JSONP = require('./jsonp');
var timeoutWatchers = [];

function deserialize(response, mapper) {
  if (response.status >= 400) {
    return [response, null];
  } else {
    return [null, mapper(response)];
  }
}

function noop() {}

function requestWithTimeout(url, attrs, deserializer, method, callback, timeout) {
  var uniqueName;

  callback = callback || noop;

  if (timeout == null) {
    timeout = 60000;
  }

  uniqueName = method(url, attrs, function (data, name) {
    if (timeoutWatchers[name]) {
      clearTimeout(timeoutWatchers[name]);
      callback.apply(null, deserialize(data, function (d) { return deserializer(d); }));
    }
  });

  if (typeof timeout === 'number') {
    timeoutWatchers[uniqueName] = setTimeout(function () {
      timeoutWatchers[uniqueName] = null;
      callback.apply(null, [{errors: 'Unknown error'}, null]);
    }, timeout);
  } else {
    callback.apply(null, [{errors: 'Timeout must be a number'}, null]);
  }
}

function post(url, attrs, deserializer, callback, timeout) {
  attrs._method = 'POST';
  requestWithTimeout(url, attrs, deserializer, JSONP.get, callback, timeout);
}

function get(url, attrs, deserializer, callback, timeout) {
  requestWithTimeout(url, attrs, deserializer, JSONP.get, callback, timeout);
}

function put(url, attrs, deserializer, callback, timeout) {
  attrs._method = 'PUT';
  requestWithTimeout(url, attrs, deserializer, JSONP.get, callback, timeout);
}

module.exports = {
  get: get,
  post: post,
  put: put
};

},{"./jsonp":8}],8:[function(require,module,exports){
(function (global){
'use strict';

var util = require('./util');

/*
* Lightweight JSONP fetcher
* Copyright 2010-2012 Erik Karlsson. All rights reserved.
* BSD licensed
*/
var head,
    window = global,
    config = {};

function load(url, pfnError) {
  var script = document.createElement('script'),
  done = false;
  script.src = url;
  script.async = true;

  var errorHandler = pfnError || config.error;
  if ( typeof errorHandler === 'function' ) {
    script.onerror = function (ex){
      errorHandler({url: url, event: ex});
    };
  }

  script.onload = script.onreadystatechange = function () {
    if ( !done && (!this.readyState || this.readyState === "loaded" || this.readyState === "complete") ) {
      done = true;
      script.onload = script.onreadystatechange = null;
      if ( script && script.parentNode ) {
        script.parentNode.removeChild( script );
      }
    }
  };

  if ( !head ) {
    head = document.getElementsByTagName('head')[0];
  }
  head.appendChild( script );
}

function encode(str) {
  return encodeURIComponent(str);
}

function stringify(params, namespace) {
  var query = [], k, v, p;
  for(var p in params) {
    if (!params.hasOwnProperty(p)) {
      continue;
    }

    v = params[p];
    if (namespace) {
      if (util.isArray(params)) {
        k = namespace + "[]";
      } else {
        k = namespace + "[" + p + "]";
      }
    } else {
      k = p;
    }
    if (typeof v == "object") {
      query.push(stringify(v, k));
    } else {
      query.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    }
  }
  return query.join("&");
}

function jsonp(url, params, callback, callbackName) {
  var query = (url||'').indexOf('?') === -1 ? '?' : '&', key;

  callbackName = (callbackName||config['callbackName']||'callback');
  var uniqueName = callbackName + "_json" + util.generateUUID();

  query += stringify(params);

  window[ uniqueName ] = function (data){
    callback(data, uniqueName);
    try {
      delete window[ uniqueName ];
    } catch (e) {}
    window[ uniqueName ] = null;
  };

  load(url + query + '&' + callbackName + '=' + uniqueName);
  return uniqueName;
}

function setDefaults(obj){
  config = obj;
}

module.exports = {
  get: jsonp,
  init: setDefaults,
  stringify: stringify
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./util":15}],9:[function(require,module,exports){
'use strict';

function normalizeCreditCardFields(attrs) {
  var key;
  var creditCard = {
    billingAddress: attrs.billingAddress || {}
  };

  for (key in attrs) {
    if (!attrs.hasOwnProperty(key)) { continue; }

    switch (key.replace(/_/, '').toLowerCase()) {
      case 'postalcode':
      case 'countryname':
      case 'countrycodenumeric':
      case 'countrycodealpha2':
      case 'countrycodealpha3':
      case 'region':
      case 'extendedaddress':
      case 'locality':
      case 'firstname':
      case 'lastname':
      case 'company':
      case 'streetaddress':
        creditCard.billingAddress[key] = attrs[key];
        break;
      default:
        creditCard[key] = attrs[key];
    }
  }

  return creditCard;
}

module.exports = {
  normalizeCreditCardFields: normalizeCreditCardFields
};

},{}],10:[function(require,module,exports){
'use strict';

var braintreeUtils = require('braintree-utilities');
require('./polyfill');

function parseClientToken(rawClientToken) {
  var clientToken;

  if (!rawClientToken) {
    throw new Error('Braintree API Client Misconfigured: clientToken required.');
  }

  if (typeof rawClientToken === 'object' && rawClientToken !== null) {
    clientToken = rawClientToken;
  } else {
    try {
      rawClientToken = window.atob(rawClientToken);
    } catch (b64Error) {}

    try {
      clientToken = JSON.parse(rawClientToken);
    } catch (jsonError) {
      throw new Error('Braintree API Client Misconfigured: clientToken is invalid.');
    }
  }

  if (!clientToken.hasOwnProperty('clientApiUrl') || !braintreeUtils.isWhitelistedDomain(clientToken.clientApiUrl)) {
    throw new Error('Braintree API Client Misconfigured: clientToken is invalid.');
  }

  return clientToken;
}

module.exports = parseClientToken;

},{"./polyfill":12,"braintree-utilities":38}],11:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'nonce',
  'type',
  'description',
  'details'
];

function PayPalAccount(attributes) {
  var i, attribute;

  for (i = 0; i < ATTRIBUTES.length; i++) {
    attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = PayPalAccount;

},{}],12:[function(require,module,exports){
(function (global){
'use strict';

global.atob = global.atob || function (base64String) {
  var base64Matcher = new RegExp("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})([=]{1,2})?$");
  var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var result = "";

  if (!base64Matcher.test(base64String)) {
    throw new Error("Braintree API Client Misconfigured: clientToken is invalid.");
  }

  var i = 0;
  do {
    var b1 = characters.indexOf( base64String.charAt(i++) );
    var b2 = characters.indexOf( base64String.charAt(i++) );
    var b3 = characters.indexOf( base64String.charAt(i++) );
    var b4 = characters.indexOf( base64String.charAt(i++) );

    var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );
    var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );
    var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );

    result += String.fromCharCode(a) + (b?String.fromCharCode(b):"") + (c?String.fromCharCode(c):"");

  } while( i < base64String.length );

  return result;
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],13:[function(require,module,exports){
'use strict';

var JSONPDriver = require('./jsonp-driver');

module.exports = JSONPDriver;

},{"./jsonp-driver":7}],14:[function(require,module,exports){
'use strict';

function SEPAMandate(attributes) {
  var i = 0;
  var attribute;
  var allAttributes = [
    'accountHolderName',
    'bic',
    'longFormURL',
    'mandateReferenceNumber',
    'maskedIBAN',
    'shortForm'
  ];

  for (i = 0; i < allAttributes.length; i++) {
    attribute = allAttributes[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = SEPAMandate;

},{}],15:[function(require,module,exports){
'use strict';

function joinUrlFragments(fragments) {
  var strippedFragments = [],
  strippedFragment,
  i;

  for (i = 0; i < fragments.length; i++) {
    strippedFragment = fragments[i];
    if (strippedFragment.charAt(strippedFragment.length - 1) === '/') {
      strippedFragment = strippedFragment.substring(0, strippedFragment.length - 1);
    }
    if (strippedFragment.charAt(0) === '/') {
      strippedFragment = strippedFragment.substring(1);
    }

    strippedFragments.push(strippedFragment);
  }

  return strippedFragments.join('/');
}

function isArray(value) {
  return value && typeof value === 'object' && typeof value.length === 'number' &&
    Object.prototype.toString.call(value) === '[object Array]' || false;
}

function generateUUID() { // RFC 4122 v4 (pseudo-random) UUID without hyphens
  return 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, function (xORy) {
    var randomHex = Math.floor(Math.random() * 16);
    var uuidHex = xORy === 'x' ? randomHex : randomHex & 0x3 | 0x8; // jshint ignore:line
    return uuidHex.toString(16);
  });
}

function mergeOptions(obj1, obj2) {
  var obj3 = {};
  var attrname;
  for (attrname in obj1) {
    if (obj1.hasOwnProperty(attrname)) {
      obj3[attrname] = obj1[attrname];
    }
  }
  for (attrname in obj2) {
    if (obj2.hasOwnProperty(attrname)) {
      obj3[attrname] = obj2[attrname];
    }
  }
  return obj3;
}

module.exports = {
  joinUrlFragments: joinUrlFragments,
  isArray: isArray,
  generateUUID: generateUUID,
  mergeOptions: mergeOptions
};

},{}],16:[function(require,module,exports){
'use strict';

var Client = require('./lib/client');
var JSONP = require('./lib/jsonp');
var JSONPDriver = require('./lib/jsonp-driver');
var util = require('./lib/util');
var parseClientToken = require('./lib/parse-client-token');
var getConfiguration = require('./lib/get-configuration');

function configure(options) {
  return new Client(options);
}

module.exports = {
  Client: Client,
  configure: configure,
  util: util,
  JSONP: JSONP,
  JSONPDriver: JSONPDriver,
  parseClientToken: parseClientToken,
  getConfiguration: getConfiguration
};

},{"./lib/client":2,"./lib/get-configuration":6,"./lib/jsonp":8,"./lib/jsonp-driver":7,"./lib/parse-client-token":10,"./lib/util":15}],17:[function(require,module,exports){
'use strict';

var nativeIndexOf = Array.prototype.indexOf;

var indexOf;
if (nativeIndexOf) {
  indexOf = function (haystack, needle) {
    return haystack.indexOf(needle);
  };
} else {
  indexOf = function indexOf(haystack, needle) {
    for (var i = 0, len = haystack.length; i < len; i++) {
      if (haystack[i] === needle) {
        return i;
      }
    }
    return -1;
  };
}

module.exports = {
  indexOf: indexOf
};

},{}],18:[function(require,module,exports){
'use strict';

function normalizeElement (element, errorMessage) {
  errorMessage = errorMessage || '[' + element + '] is not a valid DOM Element';

  if (element && element.nodeType && element.nodeType === 1) {
    return element;
  }
  if (element && window.jQuery && (element instanceof jQuery || 'jquery' in Object(element)) && element.length !== 0) {
    return element[0];
  }

  if (typeof element === 'string' && document.getElementById(element)) {
    return document.getElementById(element);
  }

  throw new Error(errorMessage);
}

module.exports = {
  normalizeElement: normalizeElement
};

},{}],19:[function(require,module,exports){
'use strict';

function addEventListener(element, type, listener, useCapture) {
  if (element.addEventListener) {
    element.addEventListener(type, listener, useCapture);
  } else if (element.attachEvent) {
    element.attachEvent('on' + type, listener);
  }
}

function removeEventListener(element, type, listener, useCapture) {
  if (element.removeEventListener) {
    element.removeEventListener(type, listener, useCapture);
  } else if (element.detachEvent) {
    element.detachEvent('on' + type, listener);
  }
}

module.exports = {
  addEventListener: addEventListener,
  removeEventListener: removeEventListener
};

},{}],20:[function(require,module,exports){
'use strict';

var toString = Object.prototype.toString;

function isFunction(func) {
  return toString.call(func) === '[object Function]';
}

function bind(func, context) {
  return function () {
    func.apply(context, arguments);
  };
}

module.exports = {
  bind: bind,
  isFunction: isFunction
};

},{}],21:[function(require,module,exports){
'use strict';

function getMaxCharLength(width) {
  var max, i, range, len;
  var ranges = [
    { min: 0, max: 180, chars: 7 },
    { min: 181, max: 620, chars: 14 },
    { min: 621, max: 960, chars: 22 }
  ];

  len = ranges.length;

  width = width || window.innerWidth;

  for (i = 0; i < len; i++) {
    range = ranges[i];

    if (width >= range.min && width <= range.max) {
      max = range.chars;
    }
  }

  return max || 60;
}

function truncateEmail(email, maxLength) {
  var address, domain;

  if (email.indexOf('@') === -1) {
    return email;
  }

  email = email.split('@');
  address = email[0];
  domain = email[1];

  if (address.length > maxLength) {
    address = address.slice(0, maxLength) + '...';
  }

  if (domain.length > maxLength) {
    domain = '...' + domain.slice(-maxLength);
  }

  return address + '@' + domain;
}

module.exports = {
  truncateEmail: truncateEmail,
  getMaxCharLength: getMaxCharLength
};

},{}],22:[function(require,module,exports){
'use strict';

var array = require('./array');

function isBrowserHttps() {
  return window.location.protocol === 'https:';
}

function encode(str) {
  switch (str) {
    case null:
    case undefined:
      return '';
    case true:
      return '1';
    case false:
      return '0';
    default:
      return encodeURIComponent(str);
  }
}

function makeQueryString(params, namespace) {
  var query = [], k, p;
  for (p in params) {
    if (params.hasOwnProperty(p)) {
      var v = params[p];
      if (namespace) {
        k = namespace + '[' + p + ']';
      } else {
        k = p;
      }
      if (typeof v === 'object') {
        query.push(makeQueryString(v, k));
      } else if (v !== undefined && v !== null) {
        query.push(encode(k) + '=' + encode(v));
      }
    }
  }
  return query.join('&');
}

function decodeQueryString(queryString) {
  var params = {},
  paramPairs = queryString.split('&');

  for (var i = 0; i < paramPairs.length; i++) {
    var paramPair = paramPairs[i].split('=');
    var key = paramPair[0];
    var value = decodeURIComponent(paramPair[1]);
    params[key] = value;
  }

  return params;
}

function getParams(url) {
  var urlSegments = url.split('?');

  if (urlSegments.length !== 2) {
    return {};
  }

  return decodeQueryString(urlSegments[1]);
}

var parser = document.createElement('a');
var legalHosts = [
  'paypal.com',
  'braintreepayments.com',
  'braintreegateway.com',
  'localhost'
];

function isWhitelistedDomain(url) {
  url = url.toLowerCase();

  if (!/^http/.test(url)) {
    return false;
  }

  parser.href = url;

  var pieces = parser.hostname.split('.');
  var topLevelDomain = pieces.slice(-2).join('.');

  if (array.indexOf(legalHosts, topLevelDomain) === -1) {
    return false;
  }

  return true;
}

module.exports = {
  isBrowserHttps: isBrowserHttps,
  makeQueryString: makeQueryString,
  decodeQueryString: decodeQueryString,
  getParams: getParams,
  isWhitelistedDomain: isWhitelistedDomain
};

},{"./array":17}],23:[function(require,module,exports){
var dom = require('./lib/dom');
var url = require('./lib/url');
var fn = require('./lib/fn');
var events = require('./lib/events');
var string = require('./lib/string');
var array = require('./lib/array');

module.exports = {
  string: string,
  array: array,
  normalizeElement: dom.normalizeElement,
  isBrowserHttps: url.isBrowserHttps,
  makeQueryString: url.makeQueryString,
  decodeQueryString: url.decodeQueryString,
  getParams: url.getParams,
  isWhitelistedDomain: url.isWhitelistedDomain,
  removeEventListener: events.removeEventListener,
  addEventListener: events.addEventListener,
  bind: fn.bind,
  isFunction: fn.isFunction
};

},{"./lib/array":17,"./lib/dom":18,"./lib/events":19,"./lib/fn":20,"./lib/string":21,"./lib/url":22}],24:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');
var Receiver = require('../shared/receiver');
var version = "1.2.0";

var htmlNode, bodyNode;

function getElementStyle(element, style) {
  var computedStyle = window.getComputedStyle ? getComputedStyle(element) : element.currentStyle;

  return computedStyle[style];
}

function getMerchantPageDefaultStyles() {
  return {
    html: {
      height: htmlNode.style.height || '',
      overflow: getElementStyle(htmlNode, 'overflow'),
      position: getElementStyle(htmlNode, 'position')
    },
    body: {
      height: bodyNode.style.height || '',
      overflow: getElementStyle(bodyNode, 'overflow')
    }
  };
}

function AuthenticationService (assetsUrl, container) {
  this.assetsUrl = assetsUrl;
  this.container = container || document.body;
  this.iframe = null;

  htmlNode = document.documentElement;
  bodyNode = document.body;
  this.merchantPageDefaultStyles = getMerchantPageDefaultStyles();
}

AuthenticationService.prototype.get = function (response, callback) {
  var self = this,
  url = this.constructAuthorizationURL(response);

  if (this.container && utils.isFunction(this.container)) {
    this.container(url + '&no_style=1');
  } else {
    this.insertIframe(url);
  }

  new Receiver(function (response) {
    if (!utils.isFunction(self.container)) {
      self.removeIframe();
    }
    callback(response);
  });
};

AuthenticationService.prototype.removeIframe = function () {
  if (this.container && this.container.nodeType && this.container.nodeType === 1) {
    this.container.removeChild(this.iframe);
  } else if (this.container && window.jQuery && this.container instanceof jQuery) {
    $(this.iframe, this.container).remove();
  } else if (typeof this.container === 'string') {
    document.getElementById(this.container).removeChild(this.iframe);
  }

  this.unlockMerchantWindowSize();
};

AuthenticationService.prototype.insertIframe = function (url) {
  // TODO: Security - This takes a url and makes an iframe. Doesn't seem like this would be a problem.
  var iframe = document.createElement('iframe');
  iframe.src = url;
  this.applyStyles(iframe);
  this.lockMerchantWindowSize();

  if (this.container && this.container.nodeType && this.container.nodeType === 1) {
    this.container.appendChild(iframe);
  } else if (this.container && window.jQuery && this.container instanceof jQuery && this.container.length !== 0) {
    this.container.append(iframe);
  } else if (typeof this.container === 'string' && document.getElementById(this.container)) {
    document.getElementById(this.container).appendChild(iframe);
  } else {
    throw new Error('Unable to find valid container for iframe.');
  }
  this.iframe = iframe;
};

AuthenticationService.prototype.applyStyles = function (iframe) {
  iframe.style.position = 'fixed';
  iframe.style.top = '0';
  iframe.style.left = '0';
  iframe.style.height = '100%';
  iframe.style.width = '100%';
  iframe.setAttribute('frameborder', '0');
  iframe.setAttribute('allowTransparency', 'true');
  iframe.style.border = '0';
  iframe.style.zIndex = '99999';
};

AuthenticationService.prototype.lockMerchantWindowSize = function () {
  htmlNode.style.overflow = 'hidden';
  bodyNode.style.overflow = 'hidden';
  bodyNode.style.height = '100%';
};

AuthenticationService.prototype.unlockMerchantWindowSize = function () {
  var defaultStyles = this.merchantPageDefaultStyles;

  bodyNode.style.height = defaultStyles.body.height;
  bodyNode.style.overflow = defaultStyles.body.overflow;

  htmlNode.style.overflow = defaultStyles.html.overflow;
};

AuthenticationService.prototype.constructAuthorizationURL = function (response) {
  var queryString,
  parentURL = window.location.href;

  if (parentURL.indexOf('#') > -1) {
    parentURL = parentURL.split('#')[0];
  }

  queryString = utils.makeQueryString({
    acsUrl: response.acsUrl,
    pareq: response.pareq,
    termUrl: response.termUrl + '&three_d_secure_version=' + version,
    md: response.md,
    parentUrl: parentURL
  });
  return this.assetsUrl + '/3ds/' + version + '/html/style_frame?' + queryString;
};

module.exports = AuthenticationService;

},{"../shared/receiver":31,"braintree-utilities":23}],25:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');
var AuthenticationService = require('./authorization_service');
var Loader = require('./loader');

function noop() {}

function Client(api, options) {
  options = options || {};
  this.clientToken = options.clientToken;
  this.container = options.container;
  this.api = api;
  this.nonce = null;

  this._loader = null;
  this._boundHandleUserClose = utils.bind(this._handleUserClose, this);
}

Client.prototype.verify = function (data, callback) {
  if (!utils.isFunction(callback)) {
    this.api.sendAnalyticsEvents('3ds.web.no_callback');
    throw new Error('No suitable callback argument was given');
  }
  if (utils.isFunction(data.onUserClose)) {
    this._onUserClose = data.onUserClose;
  }
  if (utils.isFunction(data.onLookupComplete)) {
    this._onLookupComplete = data.onLookupComplete;
  }
  if (data.useDefaultLoader === undefined || data.useDefaultLoader === true) {
    this._createDefaultLoader();
  }

  var dataRecord = {nonce: '', amount: data.amount};
  var creditCardMetaData = data.creditCard;

  if (typeof creditCardMetaData === 'string') {
    dataRecord.nonce = creditCardMetaData;
    this.api.sendAnalyticsEvents('3ds.web.verify.nonce');
    this.startVerification(dataRecord, callback);
  } else {
    var self = this;
    var boundHandleTokenizeCard = function (err, nonce) {
      if (err) {
        self._removeDefaultLoader();

        return callback(err);
      }
      dataRecord.nonce = nonce;
      self.startVerification(dataRecord, callback);
    };
    this.api.sendAnalyticsEvents('3ds.web.verify.credit_card');
    this.api.tokenizeCard(creditCardMetaData, boundHandleTokenizeCard);
  }
};

Client.prototype.startVerification = function (data, merchantCallback) {
  this.api.lookup3DS(data, utils.bind(this.handleLookupResponse(merchantCallback), this));
};

Client.prototype.handleLookupResponse = function (merchantCallback) {
  var self = this;
  return function (errorResponse, lookupResponse) {
    var authenticationService;

    this._onLookupComplete();

    if (errorResponse) {
      merchantCallback(errorResponse.error);
    } else if (lookupResponse.lookup && lookupResponse.lookup.acsUrl && lookupResponse.lookup.acsUrl.length > 0) {
      self.nonce = lookupResponse.paymentMethod.nonce;
      authenticationService = new AuthenticationService(this.clientToken.assetsUrl, this.container);
      authenticationService.get(lookupResponse.lookup, utils.bind(this.handleAuthenticationResponse(merchantCallback), this));

      this._detachListeners();
      this._attachListeners();
    } else {
      self.nonce = lookupResponse.paymentMethod.nonce;
      merchantCallback(null, {
        nonce: self.nonce,
        verificationDetails: lookupResponse.threeDSecureInfo
      });
    }
  };
};

Client.prototype.handleAuthenticationResponse = function (merchantCallback) {
  return function (authResponseQueryString) {
    var authResponse,
        queryParams = utils.decodeQueryString(authResponseQueryString);

    if (queryParams.user_closed) {
      return;
    }

    authResponse = JSON.parse(queryParams.auth_response);

    if (authResponse.success) {
      merchantCallback(null, {
        nonce: authResponse.paymentMethod.nonce,
        verificationDetails: authResponse.threeDSecureInfo
      });
    } else if (authResponse.threeDSecureInfo && authResponse.threeDSecureInfo.liabilityShiftPossible) {
      merchantCallback(null, {
        nonce: this.nonce,
        verificationDetails: authResponse.threeDSecureInfo
      });
    } else {
      merchantCallback(authResponse.error);
    }
  };
};

Client.prototype._attachListeners = function () {
  utils.addEventListener(window, 'message', this._boundHandleUserClose);
};

Client.prototype._detachListeners = function () {
  utils.removeEventListener(window, 'message', this._boundHandleUserClose);
};

Client.prototype._createDefaultLoader = function () {
  this._loader = new Loader();

  document.body.appendChild(this._loader.getElement());
};

Client.prototype._removeDefaultLoader = function () {
  if (!this._loader) {
    return;
  }

  var loaderElement = this._loader.getElement();
  var parentElement = loaderElement.parentNode;

  if (parentElement) {
    parentElement.removeChild(loaderElement);
  }

  this._loader.dispose();
  this._loader = null;
};

Client.prototype._handleUserClose = function (event) {
  if (event.data === 'user_closed=true') {
    this._onUserClose();
  }
};

Client.prototype._onUserClose = noop;

Client.prototype._onLookupComplete = function () {
  this._removeDefaultLoader();
};

module.exports = Client;

},{"./authorization_service":24,"./loader":27,"braintree-utilities":23}],26:[function(require,module,exports){
'use strict';

var Client = require('./client');

module.exports = {
  create: function (clientToken, options) {
    var client = new Client(clientToken, options);
    return client;
  }
};

},{"./client":25}],27:[function(require,module,exports){
'use strict';

var LoaderDisplay = require('./loader_display');
var LoaderMessage = require('./loader_message');
var LoaderSpinner = require('./loader_spinner');

function Loader() {
  this._element = document.createElement('div');
  this._element.style.cssText = this._cssDeclarations;

  this._display = null;

  this._initialize();
}

Loader.prototype._cssDeclarations = [
  'filter:progid:DXImageTransform.Microsoft.Gradient(StartColorStr=#7F000000, EndColorStr=#7F000000)',
  'background-color: rgba(0, 0, 0, 0.5)',
  'display: table',
  'height: 100%',
  'left: 0',
  'position: fixed',
  'right: 0',
  'top: 0',
  'width: 100%',
  'z-index: 99999'
].join(';');

Loader.prototype.getElement = function () {
  return this._element;
};

Loader.prototype.dispose = function () {
  this._display.dispose();
  this._display = null;

  this._element = null;
};

Loader.prototype._initialize = function () {
  var displayObject = new LoaderSpinner();
  var supportsSvgAnimations = (window.SVGElement && window.SVGAnimateElement &&
                               window.SVGAnimateTransformElement);

  if (!(supportsSvgAnimations)) {
    displayObject = new LoaderMessage('Loading...');
  }

  this._display = new LoaderDisplay(displayObject);
  this.getElement().appendChild(this._display.getElement());
};

module.exports = Loader;

},{"./loader_display":28,"./loader_message":29,"./loader_spinner":30}],28:[function(require,module,exports){
'use strict';

function LoaderDisplay(displayObject) {
  this._element = document.createElement('div');
  this._element.style.cssText = this._cssDeclarations;

  this._displayObject = displayObject;

  this._initialize();
}

LoaderDisplay.prototype._cssDeclarations = [
  'display: table-cell',
  'vertical-align: middle'
].join(';');

LoaderDisplay.prototype.getElement = function () {
  return this._element;
};

LoaderDisplay.prototype.dispose = function () {
  this._displayObject.dispose();
  this._displayObject = null;

  this._element = null;
};

LoaderDisplay.prototype._initialize = function () {
  this.getElement().appendChild(this._displayObject.getElement());
};

module.exports = LoaderDisplay;

},{}],29:[function(require,module,exports){
'use strict';

function LoaderMessage(text) {
  this._element = document.createElement('div');
  this._element.style.cssText = this._cssDeclarations;
  this._element.innerHTML = text;
}

LoaderMessage.prototype._cssDeclarations = [
  'color: #fff',
  'font-family: Helvetica, sans-serif',
  'font-size: 12px',
  'text-align: center'
].join(';');

LoaderMessage.prototype.getElement = function () {
  return this._element;
};

LoaderMessage.prototype.dispose = function () {
  this._element = null;
};

module.exports = LoaderMessage;

},{}],30:[function(require,module,exports){
'use strict';

function LoaderSpinner() {
  this._element = document.createElement('div');
  this._element.style.cssText = this._cssDeclarations;
  this._element.innerHTML = this._markup;
}

LoaderSpinner.prototype._cssDeclarations = [
  'height: 36px',
  'margin-left: auto',
  'margin-right: auto',
  'width: 36px'
].join(';');

LoaderSpinner.prototype._markup = [
  '<svg version="1.1" id="loader-1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"',
  'width="100%" height="100%" viewBox="0 0 50 50" style="enable-background:new 0 0 50 50;" xml:space="preserve">',
  '  <path fill="#FFF" d="M43.935,25.145c0-10.318-8.364-18.683-18.683-18.683c-10.318,0-18.683,8.365-18.683,18.683h4.068c0-8.071,6.543-14.615,14.615-14.615c8.072,0,14.615,6.543,14.615,14.615H43.935z">',
  '    <animateTransform attributeType="xml"',
  '    attributeName="transform"',
  '    type="rotate"',
  '    from="0 25 25"',
  '    to="360 25 25"',
  '    dur="780ms"',
  '    repeatCount="indefinite"',
  '    calcMode="spline"',
  '    keySplines="0.44, 0.22, 0, 1"',
  '    keyTimes="0;1"/>',
  '  </path>',
  '</svg>'
].join('');

LoaderSpinner.prototype.getElement = function () {
  return this._element;
};

LoaderSpinner.prototype.dispose = function () {
  this._element = null;
};

module.exports = LoaderSpinner;

},{}],31:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function Receiver (callback) {
  this.postMessageReceiver(callback);
  this.hashChangeReceiver(callback);
}

Receiver.prototype.postMessageReceiver = function (callback) {
  var self = this;

  this.wrappedCallback = function (event) {
    var data = event.data;

    if (/^(auth_response=)/.test(data) || data === 'user_closed=true') {
      callback(data);
      self.stopListening();
    }
  };

  utils.addEventListener(window, 'message', this.wrappedCallback);
};

Receiver.prototype.hashChangeReceiver = function (callback) {
  var hash,
      originalHash = window.location.hash,
      self = this;

  this.poll = setInterval(function () {
    hash = window.location.hash;

    if (hash.length > 0 && (hash !== originalHash)) {
      self.stopListening();

      hash = hash.substring(1, hash.length);
      callback(hash);

      if (originalHash.length > 0) {
        window.location.hash = originalHash;
      } else {
        window.location.hash = '';
      }
    }
  }, 10);
};

Receiver.prototype.stopListening = function () {
  clearTimeout(this.poll);

  utils.removeEventListener(window, 'message', this.wrappedCallback);
};

module.exports = Receiver;

},{"braintree-utilities":23}],32:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],33:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],34:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],35:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],36:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],37:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":32,"dup":22}],38:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":32,"./lib/dom":33,"./lib/events":34,"./lib/fn":35,"./lib/string":36,"./lib/url":37,"dup":23}],39:[function(require,module,exports){
'use strict';

var bus = require('framebus');
bus.events = require('./lib/events');

module.exports = bus;

},{"./lib/events":40,"framebus":41}],40:[function(require,module,exports){
'use strict';

var eventList = [
  'PAYMENT_METHOD_REQUEST',
  'PAYMENT_METHOD_RECEIVED',
  'PAYMENT_METHOD_GENERATED',
  'PAYMENT_METHOD_NOT_GENERATED',
  'PAYMENT_METHOD_CANCELLED',
  'PAYMENT_METHOD_ERROR',
  'CONFIGURATION_REQUEST',
  'ROOT_METADATA_REQUEST',
  'ERROR',
  'WARNING',
  'UI_POPUP_DID_OPEN',
  'UI_POPUP_DID_CLOSE',
  'UI_POPUP_FORCE_CLOSE',
  'ASYNC_DEPENDENCY_INITIALIZING',
  'ASYNC_DEPENDENCY_READY'
];
var eventEnum = {};

for (var i = 0; i < eventList.length; i++) {
  var evnt = eventList[i];
  eventEnum[evnt] = evnt;
}

module.exports = eventEnum;

},{}],41:[function(require,module,exports){
'use strict';
(function (root, factory) {
  if (typeof exports === 'object' && typeof module !== 'undefined') {
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else {
    root.framebus = factory();
  }
})(this, function () {
  var win;
  var subscribers = {};

  function publish(event, data, origin) {
    var payload;
    origin = origin || '*';
    if (typeof event !== 'string') { return false; }
    if (typeof origin !== 'string') { return false; }

    payload = _packagePayload(event, data, origin);
    if (payload === false) { return false; }

    _broadcast(win.top, payload, origin);

    return true;
  }

  function subscribe(event, fn, origin) {
    origin = origin || '*';
    if (_subscriptionArgsInvalid(event, fn, origin)) { return false; }

    subscribers[origin] = subscribers[origin] || {};
    subscribers[origin][event] = subscribers[origin][event] || [];
    subscribers[origin][event].push(fn);

    return true;
  }

  function unsubscribe(event, fn, origin) {
    var i, subscriberList;
    origin = origin || '*';

    if (_subscriptionArgsInvalid(event, fn, origin)) { return false; }

    subscriberList = subscribers[origin] && subscribers[origin][event];
    if (!subscriberList) { return false; }

    for (i = 0; i < subscriberList.length; i++) {
      if (subscriberList[i] === fn) {
        subscriberList.splice(i, 1);
        return true;
      }
    }

    return false;
  }

  function _packagePayload(event, data, origin) {
    var packaged = false;
    var payload = { event: event };

    if (typeof data === 'function') {
      payload.reply = _subscribeReplier(data, origin);
    } else {
      payload.data = data;
    }

    try {
      packaged = JSON.stringify(payload);
    } catch (e) {
      throw new Error('Could not stringify event: ' + e.message);
    }
    return packaged;
  }

  function _unpackPayload(e) {
    var payload;

    try {
      payload = JSON.parse(e.data);
    } catch (err) {
      return false;
    }

    if (payload.event == null) { return false; }

    if (payload.reply != null) {
      payload.data = function reply(data) {
        var replyPayload = _packagePayload(payload.reply, data, e.origin);
        if (replyPayload === false) { return false; }

        e.source.postMessage(replyPayload, e.origin);
      };
    }

    return payload;
  }

  function _attach(w) {
    if (win) { return; }
    win = w;

    if (win.addEventListener) {
      win.addEventListener('message', _onmessage, false);
    } else if (win.attachEvent) {
      win.attachEvent('onmessage', _onmessage);
    } else if (win.onmessage === null) {
      win.onmessage = _onmessage;
    } else {
      win = null;
    }
  }

  function _uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      var v = c === 'x' ? r : r & 0x3 | 0x8;
      return v.toString(16);
    });
  }

  function _onmessage(e) {
    var payload;
    if (typeof e.data !== 'string') { return; }

    payload = _unpackPayload(e);
    if (!payload) { return; }

    _dispatch('*', payload.event, payload.data, e.origin);
    _dispatch(e.origin, payload.event, payload.data, e.origin);
  }

  function _dispatch(origin, event, data, eventOrigin) {
    var i;
    if (!subscribers[origin]) { return; }
    if (!subscribers[origin][event]) { return; }

    for (i = 0; i < subscribers[origin][event].length; i++) {
      subscribers[origin][event][i](data, eventOrigin);
    }
  }

  function _broadcast(frame, payload, origin) {
    var i;
    frame.postMessage(payload, origin);

    for (i = 0; i < frame.frames.length; i++) {
      _broadcast(frame.frames[i], payload, origin);
    }
  }

  function _subscribeReplier(fn, origin) {
    var uuid = _uuid();

    function replier(d, o) {
      fn(d, o);
      unsubscribe(uuid, replier, origin);
    }

    subscribe(uuid, replier, origin);
    return uuid;
  }

  function _subscriptionArgsInvalid(event, fn, origin) {
    if (typeof event !== 'string') { return true; }
    if (typeof fn !== 'function') { return true; }
    if (typeof origin !== 'string') { return true; }

    return false;
  }

  _attach(window);

  return {
    publish:                  publish,
    pub:                      publish,
    trigger:                  publish,
    emit:                     publish,
    subscribe:                subscribe,
    sub:                      subscribe,
    on:                       subscribe,
    unsubscribe:              unsubscribe,
    unsub:                    unsubscribe,
    off:                      unsubscribe
  };
});

},{}],42:[function(require,module,exports){
'use strict';

var Coinbase = require('./lib/coinbase');
var detector = require('./lib/detector');
var bus = require('braintree-bus');
var CONFIG_ERROR = 'CONFIGURATION';

function error(message, type) {
  bus.emit(bus.events.ERROR, {type: type, message: message});
}

function optionsAreValid(options) {
  options = options || {};
  var cbOptions = options.coinbase;

  if (options.apiClient == null) {
    error('settings.apiClient is required for coinbase', CONFIG_ERROR);
  } else if (!options.configuration.coinbaseEnabled) {
    error('Coinbase is not enabled for your merchant account', CONFIG_ERROR);
  } else if (!cbOptions || (!cbOptions.container && !cbOptions.button)) {
    error('Either options.coinbase.container or options.coinbase.button is required for Coinbase integrations', CONFIG_ERROR);
  } else if (cbOptions.container && cbOptions.button) {
    error('options.coinbase.container and options.coinbase.button are mutually exclusive', CONFIG_ERROR);
  } else if (!detector.isSupportedBrowser()) {
    error('Coinbase is not supported by your browser. Please consider upgrading', 'UNSUPPORTED_BROWSER');
  } else {
    return true;
  }

  return false;
}

function create(options) {
  if (optionsAreValid(options)) {
    return new Coinbase(options);
  }
}

module.exports = {create: create};

},{"./lib/coinbase":45,"./lib/detector":47,"braintree-bus":53}],43:[function(require,module,exports){
(function (global){
'use strict';

function iOSSafariVersion(userAgent) {
  userAgent = userAgent || global.navigator.userAgent;
  if (!/AppleWebKit\//.test(userAgent)) {
    return null;
  }
  if (!/Mobile\//.test(userAgent)) {
    return null;
  }

  return userAgent.replace(/.* OS ([0-9_]+) like Mac OS X.*/, '$1').replace(/_/g, '.');
}

function ieVersion(userAgent) {
  userAgent = userAgent || global.navigator.userAgent;
  var result = null;
  var match = /MSIE.(\d+)/.exec(userAgent);

  if (/Trident/.test(userAgent)) {
    result = 11;
  }

  if (match) {
    result = parseInt(match[1], 10);
  }

  return result;
}

function androidVersion(UA) {
  UA = UA || global.navigator.userAgent;
  if (!/Android/.test(UA)) { return null; }

  return UA.replace(/^.* Android ([0-9\.]+).*$/,'$1');
}

module.exports = {
  ieVersion: ieVersion,
  iOSSafariVersion: iOSSafariVersion,
  androidVersion: androidVersion
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],44:[function(require,module,exports){
'use strict';

var bus = require('braintree-bus');

function tokenize(err, payload, coinbase) {
  if (err) {
    // TODO: make payload in line with onError()
    bus.emit(bus.events.ERROR, err.error);
    coinbase._sendAnalyticsEvent('generate.nonce.failed');
    return;
  }

  bus.emit(bus.events.PAYMENT_METHOD_GENERATED, payload);
  coinbase._sendAnalyticsEvent('generate.nonce.succeeded');
}

module.exports = { tokenize: tokenize };

},{"braintree-bus":53}],45:[function(require,module,exports){
(function (global){
'use strict';

var utils = require('braintree-utilities');
var DOMComposer = require('./dom/composer');
var urlComposer = require('./url-composer');
var callbacks = require('./callbacks');
var constants = require('./constants');
var detector = require('./detector');
var bus = require('braintree-bus');

function _getPopupParams(options) {
  return {
    clientId: options.configuration.coinbase.clientId,
    redirectUrl: options.configuration.coinbase.redirectUrl,
    scopes: options.configuration.coinbase.scopes || constants.SCOPES,
    meta: {
      authorizations_merchant_account: options.configuration.coinbase.merchantAccount || ''
    }
  };
}

function Coinbase(options) {
  var context;

  this.buttonId = options.coinbase.button || constants.BUTTON_ID;
  this.apiClient = options.apiClient;
  this.assetsUrl = options.configuration.assetsUrl;
  this._onOAuthSuccess = utils.bind(this._onOAuthSuccess, this);
  this._handleButtonClick = utils.bind(this._handleButtonClick, this);
  this.popupParams = _getPopupParams(options);
  this.redirectDoneInterval = null;

  if (options.coinbase.container) {
    context = utils.normalizeElement(options.coinbase.container);
    this._insertFrame(context);
  } else {
    global.braintreeCoinbasePopupCallback = this._onOAuthSuccess;

    context = document.body;
    utils.addEventListener(context, 'click', this._handleButtonClick);

    this._sendAnalyticsEvent('initialized');
  }
}

Coinbase.prototype._sendAnalyticsEvent = function (eventName) {
  var namespace = this.apiClient.integration + '.web.coinbase.';
  this.apiClient.sendAnalyticsEvents(namespace + eventName);
};

Coinbase.prototype._insertFrame = function (container) {
  var frame = DOMComposer.createFrame({ src: this.assetsUrl +'/coinbase/' + constants.VERSION + '/coinbase-frame.html' });
  bus.emit(bus.events.ASYNC_DEPENDENCY_INITIALIZING);
  container.appendChild(frame);
};

Coinbase.prototype._onOAuthSuccess = function (data) {
  this._clearPollForRedirectDone();
  if (!data.code) {
    this._sendAnalyticsEvent('popup.denied');
    return;
  }

  bus.emit('coinbase:view:navigate', 'loading');
  this._sendAnalyticsEvent('popup.authorized');
  this.apiClient.tokenizeCoinbase({ code: data.code, query: urlComposer.getQueryString() }, utils.bind(function (err, payload) {
    callbacks.tokenize.apply(null, [err, payload, this]);
  }, this));
};

Coinbase.prototype._clearPollForRedirectDone = function () {
  if (this.redirectDoneInterval) {
    clearInterval(this.redirectDoneInterval);
    this.redirectDoneInterval = null;
    bus.emit(bus.events.UI_POPUP_DID_CLOSE, {source: constants.INTEGRATION_NAME});
  }
};

Coinbase.prototype._pollForRedirectDone = function (popup) {
  this.redirectDoneInterval = setInterval(utils.bind(function () {
    var code;

    if (popup == null || popup.closed) {
      this._sendAnalyticsEvent('popup.aborted');
      this._clearPollForRedirectDone();
      return;
    }

    try {
      if (popup.location.href === 'about:blank') { throw new Error('Not finished loading'); }
      code = utils.decodeQueryString(popup.location.search.replace(/^\?/, '')).code;
    } catch (e) {
      return;
    }

    this._onOAuthSuccess({ code: code });
    if (detector.shouldCloseFromParent()) {
      popup.close();
    }
  }, this), 100);
};

Coinbase.prototype._openPopup = function () {
  var popup;

  this._sendAnalyticsEvent('popup.started');
  popup = DOMComposer.createPopup(urlComposer.compose(this.popupParams));
  popup.focus();

  this._pollForRedirectDone(popup);

  bus.trigger(bus.events.UI_POPUP_DID_OPEN, {source: constants.INTEGRATION_NAME});
  bus.on(bus.events.UI_POPUP_FORCE_CLOSE, function (payload) {
    if (payload.target === constants.INTEGRATION_NAME) {
      popup.close();
    }
  });
};

Coinbase.prototype._handleButtonClick = function (event) {
  var target = event.target || event.srcElement;

  while (true) {
    if (target == null) { return; }
    if (target === event.currentTarget) { return; }
    if (target.id === this.buttonId) { break; }

    target = target.parentNode;
  }

  if (event && event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  this._openPopup();
};

module.exports = Coinbase;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./callbacks":44,"./constants":46,"./detector":47,"./dom/composer":49,"./url-composer":52,"braintree-bus":53,"braintree-utilities":62}],46:[function(require,module,exports){
'use strict';

module.exports = {
  BASE_URL: 'https://coinbase.com',
  ORIGIN_URL: 'https://www.coinbase.com',
  FRAME_NAME: 'braintree-coinbase-frame',
  POPUP_NAME: 'coinbase',
  BUTTON_ID: 'bt-coinbase-button',
  SCOPES: 'send',
  VERSION: "0.0.6",
  INTEGRATION_NAME: 'Coinbase'
};

},{}],47:[function(require,module,exports){
'use strict';

var browser = require('./browser');

function isSupportedBrowser() {
  var version = browser.ieVersion();
  return !version || (version > 8);
}

function shouldDisplayLollipopClose() {
  var version = browser.androidVersion();
  if (version == null) { return false; }

  return /^5/.test(version);
}

function shouldCloseFromParent() {
  return !(shouldDisplayLollipopClose() || shouldDisplayIOSClose());
}

function shouldDisplayIOSClose() {
  var version = browser.iOSSafariVersion();
  if (version == null) { return false; }

  return /^8\.0/.test(version) || /^8\.1$/.test(version);
}

module.exports = {
  isSupportedBrowser: isSupportedBrowser,
  shouldCloseFromParent: shouldCloseFromParent,
  shouldDisplayIOSClose: shouldDisplayIOSClose,
  shouldDisplayLollipopClose: shouldDisplayLollipopClose
};

},{"./browser":43}],48:[function(require,module,exports){
'use strict';

function createButton(config) {
  var button = document.createElement('button');

  config = config || {};

  button.id = config.id || 'coinbase-button';
  button.style.backgroundColor = config.backgroundColor || '#EEE';
  button.style.color = config.color || '#4597C3';
  button.style.border = config.border || '0';
  button.style.borderRadius = config.borderRadius || '6px';
  button.style.padding = config.padding || '12px';
  button.innerHTML = config.innerHTML || 'coinbase';

  return button;
}

module.exports = { create: createButton };

},{}],49:[function(require,module,exports){
'use strict';

var popup = require('./popup');
var button = require('./button');
var frame = require('./frame');

module.exports = {
  createButton: button.create,
  createPopup: popup.create,
  createFrame: frame.create
};

},{"./button":48,"./frame":50,"./popup":51}],50:[function(require,module,exports){
'use strict';

var constants = require('../constants');

function createFrame(config) {
  var iframe = document.createElement('iframe');
  iframe.src = config.src;
  iframe.id = constants.FRAME_NAME;
  iframe.name = constants.FRAME_NAME;
  iframe.allowTransparency = true;
  iframe.height = '70px';
  iframe.width = '100%';
  iframe.frameBorder = 0;
  iframe.style.padding = 0;
  iframe.style.margin = 0;
  iframe.style.border = 0;
  iframe.style.outline = 'none';
  return iframe;
}

module.exports = { create: createFrame };

},{"../constants":46}],51:[function(require,module,exports){
(function (global){
'use strict';

var constants = require('../constants');

function _stringifyParams(payload) {
  var params = [];

  for (var param in payload) {
    if (payload.hasOwnProperty(param)) {
      params.push([param, payload[param]].join('='));
    }
  }

  return params.join(',');
}

function _getParams() {
  var baseWidth = 850;
  var baseHeight = 600;

  return _stringifyParams({
    width: baseWidth,
    height: baseHeight,
    left: (screen.width - baseWidth) / 2,
    top: (screen.height - baseHeight) / 4
  });
}

function createPopup(url) {
  return global.open(url, constants.POPUP_NAME, _getParams());
}

module.exports = { create: createPopup };

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"../constants":46}],52:[function(require,module,exports){
'use strict';

var constants = require('./constants');

function getQueryString() {
  return 'version=' + constants.VERSION;
}

function compose(params) {
  var url = constants.BASE_URL + '/oauth/authorize?response_type=code';
  var redirectUri = params.redirectUrl + '?' + getQueryString();

  url += '&redirect_uri=' + encodeURIComponent(redirectUri);
  url += '&client_id=' + params.clientId;

  if (params.scopes) {
    url += '&scope=' + encodeURIComponent(params.scopes);
  }

  if (params.meta) {
    for (var key in params.meta) {
      if (params.meta.hasOwnProperty(key)) {
        url += '&meta[' + encodeURIComponent(key) + ']=' + encodeURIComponent(params.meta[key]);
      }
    }
  }

  return url;
}

module.exports = {
  compose: compose,
  getQueryString: getQueryString
};

},{"./constants":46}],53:[function(require,module,exports){
arguments[4][39][0].apply(exports,arguments)
},{"./lib/events":54,"dup":39,"framebus":55}],54:[function(require,module,exports){
arguments[4][40][0].apply(exports,arguments)
},{"dup":40}],55:[function(require,module,exports){
arguments[4][41][0].apply(exports,arguments)
},{"dup":41}],56:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],57:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],58:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],59:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],60:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],61:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":56,"dup":22}],62:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":56,"./lib/dom":57,"./lib/events":58,"./lib/fn":59,"./lib/string":60,"./lib/url":61,"dup":23}],63:[function(require,module,exports){
arguments[4][2][0].apply(exports,arguments)
},{"./coinbase-account":64,"./credit-card":65,"./europe-bank-account":66,"./normalize-api-fields":70,"./parse-client-token":71,"./paypal-account":72,"./request-driver":74,"./sepa-mandate":75,"./util":76,"braintree-3ds":87,"braintree-utilities":99,"dup":2}],64:[function(require,module,exports){
arguments[4][3][0].apply(exports,arguments)
},{"dup":3}],65:[function(require,module,exports){
arguments[4][4][0].apply(exports,arguments)
},{"dup":4}],66:[function(require,module,exports){
arguments[4][5][0].apply(exports,arguments)
},{"dup":5}],67:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./parse-client-token":71,"./request-driver":74,"./util":76,"dup":6}],68:[function(require,module,exports){
arguments[4][7][0].apply(exports,arguments)
},{"./jsonp":69,"dup":7}],69:[function(require,module,exports){
arguments[4][8][0].apply(exports,arguments)
},{"./util":76,"dup":8}],70:[function(require,module,exports){
arguments[4][9][0].apply(exports,arguments)
},{"dup":9}],71:[function(require,module,exports){
arguments[4][10][0].apply(exports,arguments)
},{"./polyfill":73,"braintree-utilities":99,"dup":10}],72:[function(require,module,exports){
arguments[4][11][0].apply(exports,arguments)
},{"dup":11}],73:[function(require,module,exports){
arguments[4][12][0].apply(exports,arguments)
},{"dup":12}],74:[function(require,module,exports){
arguments[4][13][0].apply(exports,arguments)
},{"./jsonp-driver":68,"dup":13}],75:[function(require,module,exports){
arguments[4][14][0].apply(exports,arguments)
},{"dup":14}],76:[function(require,module,exports){
arguments[4][15][0].apply(exports,arguments)
},{"dup":15}],77:[function(require,module,exports){
arguments[4][16][0].apply(exports,arguments)
},{"./lib/client":63,"./lib/get-configuration":67,"./lib/jsonp":69,"./lib/jsonp-driver":68,"./lib/parse-client-token":71,"./lib/util":76,"dup":16}],78:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],79:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],80:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],81:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],82:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],83:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":78,"dup":22}],84:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":78,"./lib/dom":79,"./lib/events":80,"./lib/fn":81,"./lib/string":82,"./lib/url":83,"dup":23}],85:[function(require,module,exports){
arguments[4][24][0].apply(exports,arguments)
},{"../shared/receiver":92,"braintree-utilities":84,"dup":24}],86:[function(require,module,exports){
arguments[4][25][0].apply(exports,arguments)
},{"./authorization_service":85,"./loader":88,"braintree-utilities":84,"dup":25}],87:[function(require,module,exports){
arguments[4][26][0].apply(exports,arguments)
},{"./client":86,"dup":26}],88:[function(require,module,exports){
arguments[4][27][0].apply(exports,arguments)
},{"./loader_display":89,"./loader_message":90,"./loader_spinner":91,"dup":27}],89:[function(require,module,exports){
arguments[4][28][0].apply(exports,arguments)
},{"dup":28}],90:[function(require,module,exports){
arguments[4][29][0].apply(exports,arguments)
},{"dup":29}],91:[function(require,module,exports){
arguments[4][30][0].apply(exports,arguments)
},{"dup":30}],92:[function(require,module,exports){
arguments[4][31][0].apply(exports,arguments)
},{"braintree-utilities":84,"dup":31}],93:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],94:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],95:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],96:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],97:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],98:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":93,"dup":22}],99:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":93,"./lib/dom":94,"./lib/events":95,"./lib/fn":96,"./lib/string":97,"./lib/url":98,"dup":23}],100:[function(require,module,exports){
arguments[4][39][0].apply(exports,arguments)
},{"./lib/events":101,"dup":39,"framebus":102}],101:[function(require,module,exports){
arguments[4][40][0].apply(exports,arguments)
},{"dup":40}],102:[function(require,module,exports){
arguments[4][41][0].apply(exports,arguments)
},{"dup":41}],103:[function(require,module,exports){
arguments[4][2][0].apply(exports,arguments)
},{"./coinbase-account":104,"./credit-card":105,"./europe-bank-account":106,"./normalize-api-fields":110,"./parse-client-token":111,"./paypal-account":112,"./request-driver":114,"./sepa-mandate":115,"./util":116,"braintree-3ds":127,"braintree-utilities":139,"dup":2}],104:[function(require,module,exports){
arguments[4][3][0].apply(exports,arguments)
},{"dup":3}],105:[function(require,module,exports){
arguments[4][4][0].apply(exports,arguments)
},{"dup":4}],106:[function(require,module,exports){
arguments[4][5][0].apply(exports,arguments)
},{"dup":5}],107:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./parse-client-token":111,"./request-driver":114,"./util":116,"dup":6}],108:[function(require,module,exports){
arguments[4][7][0].apply(exports,arguments)
},{"./jsonp":109,"dup":7}],109:[function(require,module,exports){
arguments[4][8][0].apply(exports,arguments)
},{"./util":116,"dup":8}],110:[function(require,module,exports){
arguments[4][9][0].apply(exports,arguments)
},{"dup":9}],111:[function(require,module,exports){
arguments[4][10][0].apply(exports,arguments)
},{"./polyfill":113,"braintree-utilities":139,"dup":10}],112:[function(require,module,exports){
arguments[4][11][0].apply(exports,arguments)
},{"dup":11}],113:[function(require,module,exports){
arguments[4][12][0].apply(exports,arguments)
},{"dup":12}],114:[function(require,module,exports){
arguments[4][13][0].apply(exports,arguments)
},{"./jsonp-driver":108,"dup":13}],115:[function(require,module,exports){
arguments[4][14][0].apply(exports,arguments)
},{"dup":14}],116:[function(require,module,exports){
arguments[4][15][0].apply(exports,arguments)
},{"dup":15}],117:[function(require,module,exports){
arguments[4][16][0].apply(exports,arguments)
},{"./lib/client":103,"./lib/get-configuration":107,"./lib/jsonp":109,"./lib/jsonp-driver":108,"./lib/parse-client-token":111,"./lib/util":116,"dup":16}],118:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],119:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],120:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],121:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],122:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],123:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":118,"dup":22}],124:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":118,"./lib/dom":119,"./lib/events":120,"./lib/fn":121,"./lib/string":122,"./lib/url":123,"dup":23}],125:[function(require,module,exports){
arguments[4][24][0].apply(exports,arguments)
},{"../shared/receiver":132,"braintree-utilities":124,"dup":24}],126:[function(require,module,exports){
arguments[4][25][0].apply(exports,arguments)
},{"./authorization_service":125,"./loader":128,"braintree-utilities":124,"dup":25}],127:[function(require,module,exports){
arguments[4][26][0].apply(exports,arguments)
},{"./client":126,"dup":26}],128:[function(require,module,exports){
arguments[4][27][0].apply(exports,arguments)
},{"./loader_display":129,"./loader_message":130,"./loader_spinner":131,"dup":27}],129:[function(require,module,exports){
arguments[4][28][0].apply(exports,arguments)
},{"dup":28}],130:[function(require,module,exports){
arguments[4][29][0].apply(exports,arguments)
},{"dup":29}],131:[function(require,module,exports){
arguments[4][30][0].apply(exports,arguments)
},{"dup":30}],132:[function(require,module,exports){
arguments[4][31][0].apply(exports,arguments)
},{"braintree-utilities":124,"dup":31}],133:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],134:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],135:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],136:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],137:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],138:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":133,"dup":22}],139:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":133,"./lib/dom":134,"./lib/events":135,"./lib/fn":136,"./lib/string":137,"./lib/url":138,"dup":23}],140:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function MessageBus(host) {
  this.host = host || window;
  this.handlers = [];

  utils.addEventListener(this.host, 'message', utils.bind(this.receive, this));
}

MessageBus.prototype.receive = function (event) {
  var i, message, parsed, type;

  try {
    parsed = JSON.parse(event.data);
  } catch (e) {
    return;
  }

  type = parsed.type;
  message = new MessageBus.Message(this, event.source, parsed.data);

  for (i = 0; i < this.handlers.length; i++) {
    if (this.handlers[i].type === type) {
      this.handlers[i].handler(message);
    }
  }
};

MessageBus.prototype.send = function (source, type, data) {
  source.postMessage(JSON.stringify({
    type: type,
    data: data
  }), '*');
};

MessageBus.prototype.register = function (type, handler) {
  this.handlers.push({
    type: type,
    handler: handler
  });
};

MessageBus.prototype.unregister = function (type, handler) {
  for (var i = this.handlers.length - 1; i >= 0; i--) {
    if (this.handlers[i].type === type && this.handlers[i].handler === handler) {
      return this.handlers.splice(i, 1);
    }
  }
};

MessageBus.Message = function (bus, source, content) {
  this.bus = bus;
  this.source = source;
  this.content = content;
};

MessageBus.Message.prototype.reply = function (type, data) {
  this.bus.send(this.source, type, data);
};

module.exports = MessageBus;

},{"braintree-utilities":150}],141:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function PubsubClient(bus, target) {
  this.bus = bus;
  this.target = target;
  this.handlers = [];

  this.bus.register('publish', utils.bind(this._handleMessage, this));
}

PubsubClient.prototype._handleMessage = function (message) {
  var i,
  content = message.content,
  handlers = this.handlers[content.channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      handlers[i](content.data);
    }
  }
};

PubsubClient.prototype.publish = function (channel, data) {
  this.bus.send(this.target, 'publish', { channel: channel, data: data });
};

PubsubClient.prototype.subscribe = function (channel, handler) {
  this.handlers[channel] = this.handlers[channel] || [];
  this.handlers[channel].push(handler);
};

PubsubClient.prototype.unsubscribe = function (channel, handler) {
  var i,
  handlers = this.handlers[channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      if (handlers[i] === handler) {
        handlers.splice(i, 1);
      }
    }
  }
};

module.exports = PubsubClient;

},{"braintree-utilities":150}],142:[function(require,module,exports){
'use strict';

function PubsubServer(bus) {
  this.bus = bus;
  this.frames = [];
  this.handlers = [];
}

PubsubServer.prototype.subscribe = function (channel, handler) {
  this.handlers[channel] = this.handlers[channel] || [];
  this.handlers[channel].push(handler);
};

PubsubServer.prototype.registerFrame = function (frame) {
  this.frames.push(frame);
};

PubsubServer.prototype.unregisterFrame = function (frame) {
  for (var i = 0; i < this.frames.length; i++) {
    if (this.frames[i] === frame) {
      this.frames.splice(i, 1);
    }
  }
};

PubsubServer.prototype.publish = function (channel, data) {
  var i,
  handlers = this.handlers[channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      handlers[i](data);
    }
  }

  for (i = 0; i < this.frames.length; i++) {
    this.bus.send(this.frames[i], 'publish', {
      channel: channel,
      data: data
    });
  }
};

PubsubServer.prototype.unsubscribe = function (channel, handler) {
  var i,
  handlers = this.handlers[channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      if (handlers[i] === handler) {
        handlers.splice(i, 1);
      }
    }
  }
};

module.exports = PubsubServer;

},{}],143:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function RPCClient(bus, target) {
  this.bus = bus;
  this.target = target || window.parent;
  this.counter = 0;
  this.callbacks = {};

  this.bus.register('rpc_response', utils.bind(this._handleResponse, this));
}

RPCClient.prototype._handleResponse = function (message) {
  var content = message.content,
  thisCallback = this.callbacks[content.id];

  if (typeof thisCallback === 'function') {
    thisCallback.apply(null, content.response);
    delete this.callbacks[content.id];
  }
};

RPCClient.prototype.invoke = function (method, args, callback) {
  var counter = this.counter++;

  this.callbacks[counter] = callback;
  this.bus.send(this.target, 'rpc_request', { id: counter, method: method, args: args });
};

module.exports = RPCClient;

},{"braintree-utilities":150}],144:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function RPCServer(bus) {
  this.bus = bus;
  this.methods = {};

  this.bus.register('rpc_request', utils.bind(this._handleRequest, this));
}

RPCServer.prototype._handleRequest = function (message) {
  var reply,
  content = message.content,
  args = content.args || [],
  thisMethod = this.methods[content.method];

  if (typeof thisMethod === 'function') {
    reply = function () {
      message.reply('rpc_response', {
        id: content.id,
        response: Array.prototype.slice.call(arguments)
      });
    };

    args.push(reply);

    thisMethod.apply(null, args);
  }
};

RPCServer.prototype.define = function (method, handler) {
  this.methods[method] = handler;
};

module.exports = RPCServer;

},{"braintree-utilities":150}],145:[function(require,module,exports){
var MessageBus = require('./lib/message-bus');
var PubsubClient = require('./lib/pubsub-client');
var PubsubServer = require('./lib/pubsub-server');
var RPCClient = require('./lib/rpc-client');
var RPCServer = require('./lib/rpc-server');

module.exports = {
  MessageBus: MessageBus,
  PubsubClient: PubsubClient,
  PubsubServer: PubsubServer,
  RPCClient: RPCClient,
  RPCServer: RPCServer
};

},{"./lib/message-bus":140,"./lib/pubsub-client":141,"./lib/pubsub-server":142,"./lib/rpc-client":143,"./lib/rpc-server":144}],146:[function(require,module,exports){
'use strict';

function normalizeElement (element, errorMessage) {
  errorMessage = errorMessage || '[' + element + '] is not a valid DOM Element';

  if (element && element.nodeType && element.nodeType === 1) {
    return element;
  }
  if (element && window.jQuery && element instanceof jQuery && element.length !== 0) {
    return element[0];
  }

  if (typeof element === 'string' && document.getElementById(element)) {
    return document.getElementById(element);
  }

  throw new Error(errorMessage);
}

module.exports = {
  normalizeElement: normalizeElement
};

},{}],147:[function(require,module,exports){
'use strict';

function addEventListener(context, event, handler) {
  if (context.addEventListener) {
    context.addEventListener(event, handler, false);
  } else if (context.attachEvent)  {
    context.attachEvent('on' + event, handler);
  }
}

function removeEventListener(context, event, handler) {
  if (context.removeEventListener) {
    context.removeEventListener(event, handler, false);
  } else if (context.detachEvent)  {
    context.detachEvent('on' + event, handler);
  }
}

module.exports = {
  removeEventListener: removeEventListener,
  addEventListener: addEventListener
};

},{}],148:[function(require,module,exports){
'use strict';

function isFunction(func) {
  return Object.prototype.toString.call(func) === '[object Function]';
}

function bind(func, context) {
  return function () {
    func.apply(context, arguments);
  };
}

module.exports = {
  bind: bind,
  isFunction: isFunction
};

},{}],149:[function(require,module,exports){
'use strict';

function isBrowserHttps() {
  return window.location.protocol === 'https:';
}

function encode(str) {
  switch (str) {
    case null:
    case undefined:
      return '';
    case true:
      return '1';
    case false:
      return '0';
    default:
      return encodeURIComponent(str);
  }
}

function makeQueryString(params, namespace) {
  var query = [], k, p;
  for (p in params) {
    if (params.hasOwnProperty(p)) {
      var v = params[p];
      if (namespace) {
        k = namespace + '[' + p + ']';
      } else {
        k = p;
      }
      if (typeof v === 'object') {
        query.push(makeQueryString(v, k));
      } else if (v !== undefined && v !== null) {
        query.push(encode(k) + '=' + encode(v));
      }
    }
  }
  return query.join('&');
}

function decodeQueryString(queryString) {
  var params = {},
  paramPairs = queryString.split('&');

  for (var i = 0; i < paramPairs.length; i++) {
    var paramPair = paramPairs[i].split('=');
    var key = paramPair[0];
    var value = decodeURIComponent(paramPair[1]);
    params[key] = value;
  }

  return params;
}

function getParams(url) {
  var urlSegments = url.split('?');

  if (urlSegments.length !== 2) {
    return {};
  }

  return decodeQueryString(urlSegments[1]);
}

module.exports = {
  isBrowserHttps: isBrowserHttps,
  makeQueryString: makeQueryString,
  decodeQueryString: decodeQueryString,
  getParams: getParams
};

},{}],150:[function(require,module,exports){
var dom = require('./lib/dom');
var url = require('./lib/url');
var fn = require('./lib/fn');
var events = require('./lib/events');

module.exports = {
  normalizeElement: dom.normalizeElement,
  isBrowserHttps: url.isBrowserHttps,
  makeQueryString: url.makeQueryString,
  decodeQueryString: url.decodeQueryString,
  getParams: url.getParams,
  removeEventListener: events.removeEventListener,
  addEventListener: events.addEventListener,
  bind: fn.bind,
  isFunction: fn.isFunction
};

},{"./lib/dom":146,"./lib/events":147,"./lib/fn":148,"./lib/url":149}],151:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],152:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],153:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],154:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],155:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],156:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":151,"dup":22}],157:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":151,"./lib/dom":152,"./lib/events":153,"./lib/fn":154,"./lib/string":155,"./lib/url":156,"dup":23}],158:[function(require,module,exports){
var braintreeApi = require('braintree-api');
var braintreeRpc = require('braintree-rpc');
var braintreeUtil = require('braintree-utilities');
var LoggedInView = require('./logged-in-view');
var LoggedOutView = require('./logged-out-view');
var OverlayView = require('./overlay-view');
var browser = require('../shared/util/browser');
var dom = require('../shared/util/dom');
var constants = require('../shared/constants');
var util = require('../shared/util/util');
var getLocale = require('../shared/get-locale');

function getStyles(element) {
  var computedStyles = window.getComputedStyle ? getComputedStyle(element) : element.currentStyle;
  return {
    overflow: computedStyles.overflow || '',
    height: element.style.height || ''
  };
}

function getMerchantPageDefaultStyles() {
  return {
    html: {
      node: document.documentElement,
      styles: getStyles(document.documentElement)
    },
    body: {
      node: document.body,
      styles: getStyles(document.body)
    }
  };
}

function Client(clientToken, options) {
  if (!clientToken) {
    throw new Error('Parameter "clientToken" cannot be null');
  }
  options = options || {};

  this._clientToken = braintreeApi.parseClientToken(clientToken);
  this._clientOptions = options;

  this.container = options.container;
  this.merchantPageDefaultStyles = null;
  this.paymentMethodNonceInputField = options.paymentMethodNonceInputField;
  this.frame = null;
  this.popup = null;

  this.insertFrameFunction = options.insertFrame;
  this.onSuccess = options.onSuccess;
  this.onCancelled = options.onCancelled;
  this.onUnsupported = options.onUnsupported;
  this.loggedInView = null;
  this.loggedOutView = null;

  this.insertUI = true;
}

Client.prototype.getViewerUrl = function () {
  var assetsUrl = this._clientToken.paypal.assetsUrl;
  return assetsUrl + '/pwpp/' + constants.VERSION + '/html/braintree-frame.html';
};

Client.prototype.getProxyUrl = function () {
  var assetsUrl = this._clientToken.paypal.assetsUrl;
  return assetsUrl + '/pwpp/' + constants.VERSION + '/html/proxy-frame.html';
};

Client.prototype.initialize = function () {
  if (!this._clientToken.paypalEnabled) {
    if (typeof this.onUnsupported === 'function') {
      this.onUnsupported(new Error('PayPal is not enabled'));
    }
    return;
  }
  if (!this._isBrowserSecure()) {
    if (typeof this.onUnsupported === 'function') {
      this.onUnsupported(new Error('unsupported protocol detected'));
    }
    return;
  }
  if (this._isAriesCapable()) {
    if (!this._isAriesSupportedCurrency()) {
      if (typeof this.onUnsupported === 'function') {
        this.onUnsupported(new Error('This PayPal integration does not support this currency'));
      }
      return;
    }
    if (!this._isAriesSupportedCountries()) {
      if (typeof this.onUnsupported === 'function') {
        this.onUnsupported(new Error('This PayPal integration does not support this locale'));
      }
      return;
    }
    if (!this._isValidAmount()) {
      if (typeof this.onUnsupported === 'function') {
        this.onUnsupported(new Error('Amount must be a number'));
      }
      return;
    }
  }
  if (this._isMisconfiguredUnvettedMerchant()) {
    if (typeof this.onUnsupported === 'function') {
      this.onUnsupported(new Error('Unvetted merchant client token does not include a payee email'));
    }
    return;
  }
  this._overrideClientTokenProperties();
  if (browser.isProxyFrameRequired()) {
    this._insertProxyFrame();
  }
  this._setupDomElements();
  this._setupPaymentMethodNonceInputField();
  this._setupViews();
  this._createRpcServer();
};

Client.prototype._isSupportedOption = function (option, supported) {
  var supportedLength = supported.length;
  var isSupported = false;

  for (var i = 0; i < supportedLength; i++) {
    if (option.toLowerCase() === supported[i].toLowerCase()) {
      isSupported = true;
    }
  }

  return isSupported;
};

Client.prototype._isAriesSupportedCurrency = function () {
  return this._isSupportedOption(this._clientOptions.currency, constants.ARIES_SUPPORTED_CURRENCIES);
};

Client.prototype._isAriesSupportedCountries = function () {
  return this._isSupportedOption(getLocale(this._clientOptions.locale).split('_')[1], constants.ARIES_SUPPORTED_COUNTRIES);
};

Client.prototype._isValidAmount = function () {
  var amount = parseFloat(this._clientOptions.amount);
  return (typeof amount === 'number' && !isNaN(amount) && amount >= 0);
};

Client.prototype._isMisconfiguredUnvettedMerchant = function () {
  return this._clientToken.paypal.unvettedMerchant && (!this._isAriesCapable() || !this._clientToken.paypal.payeeEmail);
};

Client.prototype._isBrowserSecure = function () {
  return braintreeUtil.isBrowserHttps() || browser.isPopupSupported() || this._clientToken.paypal.allowHttp;
};

Client.prototype._overrideClientTokenProperties = function () {
  if (this._clientOptions.displayName) {
    this._clientToken.paypal.displayName = this._clientOptions.displayName;
  }
};

Client.prototype._setupDomElements = function () {
  if (this.insertUI) {
    this.container = braintreeUtil.normalizeElement(this.container);
  }
};

Client.prototype._setupPaymentMethodNonceInputField = function () {
  if (!this.insertUI) {
    return;
  }
  var inputField = this.paymentMethodNonceInputField;
  if (!braintreeUtil.isFunction(inputField)) {
    if (inputField !== undefined) {
      inputField = braintreeUtil.normalizeElement(inputField);
    } else {
      inputField = this._createPaymentMethodNonceInputField();
    }
    this.paymentMethodNonceInputField = inputField;
  }
};

Client.prototype._setupViews = function () {
  var assetsUrl = this._clientToken.paypal.assetsUrl;
  if (this.insertUI) {
    this.loggedInView = new LoggedInView({
      container: this.container,
      assetsUrl: assetsUrl
    });
    this.loggedOutView = new LoggedOutView({
      assetsUrl: assetsUrl,
      container: this.container,
      isCheckout: this._isAriesCapable(),
      locale: this._clientOptions.locale,
      merchantId: 'merchantId'
    });

    braintreeUtil.addEventListener(this.loggedOutView.container, 'click', braintreeUtil.bind(this._handleContainerClick, this));
    braintreeUtil.addEventListener(this.loggedInView.logoutNode, 'click', braintreeUtil.bind(this._handleLogout, this));
  }
};

Client.prototype._createRpcServer = function () {
  var bus = new braintreeRpc.MessageBus(window);
  var rpc = new braintreeRpc.RPCServer(bus, window);

  rpc.define('getClientToken',
    braintreeUtil.bind(this._handleGetClientToken, this));
  rpc.define('getClientOptions',
    braintreeUtil.bind(this._handleGetClientOptions, this));
  rpc.define('closePayPalModal',
    braintreeUtil.bind(this._handleCloseMessage, this));
  rpc.define('receivePayPalData',
    braintreeUtil.bind(this._handleSuccessfulAuthentication, this));
};

Client.prototype._createPaymentMethodNonceInputField = function () {
  var input = document.createElement('input');
  input.name = 'payment_method_nonce';
  input.type = 'hidden';
  return this.container.appendChild(input);
};

Client.prototype._createFrame = function () {
  var frameName;
  var iframe = document.createElement('iframe');

  if (this._isAriesCapable()) {
    frameName = constants.ARIES_FRAME_NAME;
    iframe.style.background = '#FFFFFF';
  } else {
    frameName = constants.FRAME_NAME;
  }

  iframe.src = this.getViewerUrl();
  iframe.id = frameName;
  iframe.name = frameName;
  iframe.allowTransparency = true;
  iframe.height = '100%';
  iframe.width = '100%';
  iframe.frameBorder = 0;
  iframe.style.position = browser.isMobile() ? 'absolute' : 'fixed';
  iframe.style.top = 0;
  iframe.style.left = 0;
  iframe.style.bottom = 0;
  iframe.style.zIndex = 20001;
  iframe.style.padding = 0;
  iframe.style.margin = 0;
  iframe.style.border = 0;
  iframe.style.outline = 'none';
  return iframe;
};

Client.prototype._removeFrame = function (parent) {
  parent = parent || document.body;
  if (this.frame && parent.contains(this.frame)) {
    parent.removeChild(this.frame);
    this._unlockMerchantWindowSize();
  }
};

Client.prototype._insertFrame = function () {
  if (this.insertFrameFunction) {
    this.insertFrameFunction(this.getViewerUrl());
  } else {
    this.frame = this._createFrame();
    document.body.appendChild(this.frame);
  }
  this._lockMerchantWindowSize();
};

Client.prototype._handleContainerClick = function (event) {
  var target = event.target || event.srcElement;

  function isButton (node) {
    return node.className.match(/paypal-button(?!-widget)/) || node.id === 'braintree-paypal-button';
  }

  if (!isButton(target) && !isButton(target.parentNode)) {
    return;
  }

  if (event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  this._open();
};

Client.prototype._setMerchantPageDefaultStyles = function () {
  this.merchantPageDefaultStyles = getMerchantPageDefaultStyles();
};

Client.prototype._open = function () {
  if (this._isAriesCapable()) {
    this._addCorrelationIdToClientToken();
  }

  if (browser.isPopupSupported()) {
    this._openPopup();
  } else {
    this._openModal();
  }
};

Client.prototype._close = function () {
  if (browser.isPopupSupported()) {
    this._closePopup();
  } else {
    this._closeModal();
  }
};

Client.prototype._openModal = function () {
  this._removeFrame();
  this._insertFrame();
};

Client.prototype._isAriesCapable = function () {
  return !!this._clientOptions.singleUse && !!this._clientOptions.amount && !!this._clientOptions.currency && !this._clientOptions.demo;
};

Client.prototype._openPopup = function () {
  var name;
  var opts = [];
  var popupWidth;
  var popupHeight;
  var windowWidth = window.outerWidth || document.documentElement.clientWidth;
  var windowHeight = window.outerHeight || document.documentElement.clientHeight;
  var windowTop = typeof window.screenY === 'undefined' ? window.screenTop : window.screenY;
  var windowLeft = typeof window.screenX === 'undefined' ? window.screenLeft : window.screenX;

  if (this._isAriesCapable()) {
    name = constants.ARIES_POPUP_NAME;
    popupHeight = constants.ARIES_POPUP_HEIGHT;
    popupWidth = constants.ARIES_POPUP_WIDTH;
  } else {
    name = constants.POPUP_NAME;
    popupHeight = constants.POPUP_HEIGHT;
    popupWidth = constants.POPUP_WIDTH;
  }

  var leftPos = ((windowWidth - popupWidth) / 2) + windowLeft;
  var topPos = ((windowHeight - popupHeight) / 2) + windowTop;

  opts.push('height=' + popupHeight);
  opts.push('width=' + popupWidth);
  opts.push('top=' + topPos);
  opts.push('left=' + leftPos);
  opts.push(constants.POPUP_OPTIONS);

  this.popup = window.open(this.getViewerUrl(), name, opts.join(','));
  if (browser.isOverlaySupported()) {
    this.overlayView = new OverlayView(this.popup, this._clientToken.paypal.assetsUrl);
    this.overlayView.render();
  }
  this.popup.focus();

  return this.popup;
};

Client.prototype._addCorrelationIdToClientToken = function () {
  this._clientToken.correlationId = util.generateUid();
};

Client.prototype._createProxyFrame = function () {
  var iframe = document.createElement('iframe');

  iframe.src = this.getProxyUrl();
  iframe.id = constants.BRIDGE_FRAME_NAME;
  iframe.name = constants.BRIDGE_FRAME_NAME;
  iframe.allowTransparency = true;
  iframe.height = 0;
  iframe.width = 0;
  iframe.frameBorder = 0;
  iframe.style.position = 'static';
  iframe.style.padding = 0;
  iframe.style.margin = 0;
  iframe.style.border = 0;
  iframe.style.outline = 'none';
  return iframe;
};

Client.prototype._insertProxyFrame = function () {
  this.proxyFrame = this._createProxyFrame();
  document.body.appendChild(this.proxyFrame);
};

Client.prototype._closeModal = function () {
  this._removeFrame();
};

Client.prototype._closePopup = function () {
  if (this.popup) {
    this.popup.close();
    this.popup = null;
  }
  if (this.overlayView && browser.isOverlaySupported()) {
    this.overlayView.remove();
  }
};

Client.prototype._clientTokenData = function () {
  return {
    analyticsUrl: this._clientToken.analytics ?
      this._clientToken.analytics.url : undefined,
    authorizationFingerprint: this._clientToken.authorizationFingerprint,
    clientApiUrl: this._clientToken.clientApiUrl,
    displayName: this._clientToken.paypal.displayName,
    paypalBaseUrl: this._clientToken.paypal.assetsUrl,
    paypalClientId: this._clientToken.paypal.clientId,
    paypalPrivacyUrl: this._clientToken.paypal.privacyUrl,
    paypalUserAgreementUrl: this._clientToken.paypal.userAgreementUrl,
    unvettedMerchant: this._clientToken.paypal.unvettedMerchant,
    payeeEmail: this._clientToken.paypal.payeeEmail,
    correlationId: this._clientToken.correlationId,
    offline: this._clientOptions.offline || this._clientToken.paypal.environmentNoNetwork,
    sdkVersion: this._clientToken.sdkVersion,
    merchantAppId: this._clientToken.merchantAppId
  };
};

Client.prototype._handleGetClientToken = function (callback) {
  callback(this._clientTokenData());
};

Client.prototype._clientOptionsData = function () {
  return {
    demo: this._clientOptions.demo || false,
    locale: this._clientOptions.locale || 'en_us',
    onetime: this._clientOptions.singleUse || false,
    integration: this._clientOptions.integration || 'paypal',
    enableShippingAddress: this._clientOptions.enableShippingAddress || false,
    enableAries: this._isAriesCapable(),
    amount: this._clientOptions.amount || null,
    currency: this._clientOptions.currency || null,
    shippingAddressOverride: this._clientOptions.shippingAddressOverride || null
  };
};

Client.prototype._handleGetClientOptions = function (callback) {
  callback(this._clientOptionsData());
};

Client.prototype._handleSuccessfulAuthentication = function (bundle) {
  this._close();

  bundle.type = constants.NONCE_TYPE;

  if (braintreeUtil.isFunction(this.paymentMethodNonceInputField)) {
    this.paymentMethodNonceInputField(bundle.nonce);
  } else {
    this._showLoggedInContent(bundle.details.email);
    this._setNonceInputValue(bundle.nonce);
  }

  if (braintreeUtil.isFunction(this.onSuccess)) {
    this.onSuccess(bundle);
  }
};

Client.prototype._lockMerchantWindowSize = function () {
  this._setMerchantPageDefaultStyles();
  document.documentElement.style.height = '100%';
  document.documentElement.style.overflow = 'hidden';
  document.body.style.height = '100%';
  document.body.style.overflow = 'hidden';
};

Client.prototype._unlockMerchantWindowSize = function () {
  if (this.merchantPageDefaultStyles) {
    document.documentElement.style.height = this.merchantPageDefaultStyles.html.styles.height;
    document.documentElement.style.overflow = this.merchantPageDefaultStyles.html.styles.overflow;
    document.body.style.height = this.merchantPageDefaultStyles.body.styles.height;
    document.body.style.overflow = this.merchantPageDefaultStyles.body.styles.overflow;
  }
};

Client.prototype._handleCloseMessage = function () {
  this._removeFrame();
};

Client.prototype._showLoggedInContent = function (email) {
  this.loggedOutView.hide();

  dom.setTextContent(this.loggedInView.emailNode, email);
  this.loggedInView.show();
};

Client.prototype._handleLogout = function (event) {
  if (event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  this.loggedInView.hide();
  this.loggedOutView.show();
  this._setNonceInputValue('');

  if (braintreeUtil.isFunction(this.onCancelled)) {
    this.onCancelled();
  }
};

Client.prototype._setNonceInputValue = function (value) {
  this.paymentMethodNonceInputField.value = value;
};

module.exports = Client;

},{"../shared/constants":162,"../shared/get-locale":164,"../shared/util/browser":169,"../shared/util/dom":170,"../shared/util/util":171,"./logged-in-view":159,"./logged-out-view":160,"./overlay-view":161,"braintree-api":117,"braintree-rpc":145,"braintree-utilities":157}],159:[function(require,module,exports){
var constants = require('../shared/constants');

function LoggedInView (options) {
  this.options = options;
  this.container = this.createViewContainer();
  this.createPayPalName();
  this.emailNode = this.createEmailNode();
  this.logoutNode = this.createLogoutNode();
}

LoggedInView.prototype.createViewContainer = function () {
  var container = document.createElement('div');
  container.id = 'braintree-paypal-loggedin';
  var cssStyles = [
    'display: none',
    'max-width: 500px',
    'overflow: hidden',
    'padding: 16px',
    'background-image: url(' + this.options.assetsUrl + '/pwpp/' + constants.VERSION + '/images/paypal-small.png)',
    'background-image: url(' + this.options.assetsUrl + '/pwpp/' + constants.VERSION + '/images/paypal-small.svg), none',
    'background-position: 20px 50%',
    'background-repeat: no-repeat',
    'background-size: 13px 15px',
    'border-top: 1px solid #d1d4d6',
    'border-bottom: 1px solid #d1d4d6'
  ].join(';');
  container.style.cssText = cssStyles;
  this.options.container.appendChild(container);

  return container;
};

LoggedInView.prototype.createPayPalName = function () {
  var element = document.createElement('span');
  element.id = 'bt-pp-name';
  element.innerHTML = 'PayPal';
  var cssStyles = [
    'color: #283036',
    'font-size: 13px',
    'font-weight: 800',
    'font-family: "Helvetica Neue", Helvetica, Arial, sans-serif',
    'margin-left: 36px',
    '-webkit-font-smoothing: antialiased',
    '-moz-font-smoothing: antialiased',
    '-ms-font-smoothing: antialiased',
    'font-smoothing: antialiased'
  ].join(';');
  element.style.cssText = cssStyles;
  return this.container.appendChild(element);
};

LoggedInView.prototype.createEmailNode = function () {
  var element = document.createElement('span');
  element.id = 'bt-pp-email';
  var cssStyles = [
    'color: #6e787f',
    'font-size: 13px',
    'font-family: "Helvetica Neue", Helvetica, Arial, sans-serif',
    'margin-left: 5px',
    '-webkit-font-smoothing: antialiased',
    '-moz-font-smoothing: antialiased',
    '-ms-font-smoothing: antialiased',
    'font-smoothing: antialiased'
  ].join(';');
  element.style.cssText = cssStyles;
  return this.container.appendChild(element);
};

LoggedInView.prototype.createLogoutNode = function () {
  var element = document.createElement('button');
  element.id = 'bt-pp-cancel';
  element.innerHTML = 'Cancel';
  var cssStyles = [
    'color: #3d95ce',
    'font-size: 11px',
    'font-family: "Helvetica Neue", Helvetica, Arial, sans-serif',
    'line-height: 20px',
    'margin: 0 0 0 25px',
    'padding: 0',
    'background-color: transparent',
    'border: 0',
    'cursor: pointer',
    'text-decoration: underline',
    'float: right',
    '-webkit-font-smoothing: antialiased',
    '-moz-font-smoothing: antialiased',
    '-ms-font-smoothing: antialiased',
    'font-smoothing: antialiased'
  ].join(';');
  element.style.cssText = cssStyles;
  return this.container.appendChild(element);
};

LoggedInView.prototype.show = function () {
  this.container.style.display = 'block';
};

LoggedInView.prototype.hide = function () {
  this.container.style.display = 'none';
};

module.exports = LoggedInView;

},{"../shared/constants":162}],160:[function(require,module,exports){
var util = require('braintree-utilities');
var constants = require('../shared/constants');
var getLocale = require('../shared/get-locale');

function LoggedOutView (options) {
  this.options = options;

  this.assetsUrl = this.options.assetsUrl;
  this.container = this.createViewContainer();

  if (this.options.isCheckout) {
    this.createCheckoutWithPayPalButton();
  } else {
    this.createPayWithPayPalButton();
  }
}

LoggedOutView.prototype.createViewContainer = function () {
  var container = document.createElement('div');
  container.id = 'braintree-paypal-loggedout';

  this.options.container.appendChild(container);

  return container;
};

LoggedOutView.prototype.createPayWithPayPalButton = function () {
  var element = document.createElement('a');
  element.id = 'braintree-paypal-button';
  element.href = '#';
  var cssStyles = [
    'display: block',
    'width: 115px',
    'height: 44px',
    'overflow: hidden'
  ].join(';');
  element.style.cssText = cssStyles;

  var image = new Image();
  image.src = this.assetsUrl + '/pwpp/' + constants.VERSION + '/images/pay-with-paypal.png';
  image.setAttribute('alt', 'Pay with PayPal');
  var imageCssText = [
    'max-width: 100%',
    'display: block',
    'width: 100%',
    'height: 100%',
    'outline: none',
    'border: 0'
  ].join(';');
  image.style.cssText = imageCssText;

  element.appendChild(image);
  this.container.appendChild(element);
};

LoggedOutView.prototype.createCheckoutWithPayPalButton = function () {
  var script = document.createElement('script');
  script.src = '//www.paypalobjects.com/api/button.js';
  script.async = true;
  script.setAttribute('data-merchant', this.options.merchantId);
  script.setAttribute('data-button', 'checkout');
  script.setAttribute('data-type', 'button');
  script.setAttribute('data-width', '150');
  script.setAttribute('data-height', '44');
  script.setAttribute('data-lc', getLocale(this.options.locale));

  this.container.appendChild(script);
};

LoggedOutView.prototype.show = function () {
  this.container.style.display = 'block';
};

LoggedOutView.prototype.hide = function () {
  this.container.style.display = 'none';
};

module.exports = LoggedOutView;

},{"../shared/constants":162,"../shared/get-locale":164,"braintree-utilities":157}],161:[function(require,module,exports){
var util = require('braintree-utilities');
var constants = require('../shared/constants');

function OverlayView (popup, assetsUrl) {
  this.popup = popup;
  this.assetsUrl = assetsUrl;
  this.spriteSrc = this.assetsUrl + '/pwpp/' + constants.VERSION + '/images/pp_overlay_sprite.png';

  this._create();
  this._setupEvents();
  this._pollForPopup();
}

OverlayView.prototype.render = function () {
  if (document.body.contains(this.el)) {
    return;
  }

  document.body.appendChild(this.el);
};

OverlayView.prototype.remove = function () {
  if (document.body.contains(this.el)) {
    document.body.removeChild(this.el);
  }
};

OverlayView.prototype._create = function () {
  this.el = document.createElement('div');

  this.el.className = 'bt-overlay';

  this._setStyles(this.el, [
    'z-index: 20001',
    'position: fixed',
    'top: 0',
    'left: 0',
    'height: 100%',
    'width: 100%',
    'text-align: center',
    'background: #000',
    'background: rgba(0,0,0,0.7)',
    '-ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=52)"'
  ]);

  this.el.appendChild(this._createCloseIcon());
  this.el.appendChild(this._createMessage());
};

OverlayView.prototype._createCloseIcon = function () {
  this.closeIcon = document.createElement('div');

  this.closeIcon.className = 'bt-close-overlay';

  this._setStyles(this.closeIcon, [
    'position: absolute',
    'top: 10px',
    'right: 10px',
    'cursor: pointer',
    'background: url(' + this.spriteSrc + ') no-repeat 0 -67px',
    'height: 14px',
    'width: 14px'
  ]);

  return this.closeIcon;
};

OverlayView.prototype._createMessage = function () {
  var message = document.createElement('div');

  this._setStyles(message, [
    'position: relative',
    'top: 50%',
    'max-width: 350px',
    'font-family: "HelveticaNeue", "HelveticaNeue-Light", "Helvetica Neue Light", helvetica, arial, sans-serif',
    'font-size: 14px',
    'line-height: 20px',
    'margin: -70px auto 0'
  ]);

  message.appendChild(this._createLogo());
  message.appendChild(this._createExplanation());
  message.appendChild(this._createFocusLink());

  return message;
};

OverlayView.prototype._createExplanation = function () {
  var explanation = document.createElement('div');

  this._setStyles(explanation, [
    'color: #FFF',
    'margin-bottom: 20px'
  ]);

  explanation.innerHTML = 'Don\'t see the secure PayPal browser? We\'ll help you re-launch the window to complete your purchase.';

  return explanation;
};

OverlayView.prototype._createLogo = function () {
  var logo = document.createElement('div');

  this._setStyles(logo, [
    'background: url(' + this.spriteSrc + ') no-repeat 0 0',
    'width: 94px',
    'height: 25px',
    'margin: 0 auto 26px auto'
  ]);

  return logo;
};

OverlayView.prototype._createFocusLink = function () {
  this.focusLink = document.createElement('a');

  this._setStyles(this.focusLink, [
    'color: #009be1',
    'cursor: pointer'
  ]);

  this.focusLink.innerHTML = 'Continue';

  return this.focusLink;
};

OverlayView.prototype._setStyles = function (el, styles) {
  var cssStyles = styles.join(';');
  el.style.cssText = cssStyles;
};

OverlayView.prototype._setupEvents = function () {
  util.addEventListener(this.closeIcon, 'click', util.bind(this._handleClose, this));
  util.addEventListener(this.focusLink, 'click', util.bind(this._handleFocus, this));
};

OverlayView.prototype._handleClose = function (event) {
  event.preventDefault();
  this.remove();
  this.popup.close();
};

OverlayView.prototype._handleFocus = function (event) {
  event.preventDefault();
  this.popup.focus();
};

OverlayView.prototype._pollForPopup = function () {
  var poll = setInterval(util.bind(function () {
    if (this.popup && this.popup.closed) {
      clearInterval(poll);
      this.remove();
    }
  }, this), 100);
};

module.exports = OverlayView;

},{"../shared/constants":162,"braintree-utilities":157}],162:[function(require,module,exports){
var version = "1.3.5";

exports.VERSION = version;
exports.POPUP_NAME = 'braintree_paypal_popup';
exports.ARIES_POPUP_NAME = 'PPFrameRedirect';
exports.FRAME_NAME = 'braintree-paypal-frame';
exports.ARIES_FRAME_NAME = 'PPFrameRedirect';
exports.POPUP_PATH = '/pwpp/' + version  + '/html/braintree-frame.html';
exports.POPUP_OPTIONS = 'resizable,scrollbars';
exports.POPUP_HEIGHT = 470;
exports.POPUP_WIDTH = 410;
exports.ARIES_POPUP_HEIGHT = 535;
exports.ARIES_POPUP_WIDTH = 450;
exports.BRIDGE_FRAME_NAME = 'bt-proxy-frame';
exports.ARIES_SUPPORTED_CURRENCIES = ['USD', 'GBP', 'EUR', 'AUD', 'CAD'];
exports.ARIES_SUPPORTED_COUNTRIES = ['US', 'GB', 'AU', 'CA', 'ES', 'FR', 'DE', 'IT'];
exports.NONCE_TYPE = 'PayPalAccount';
exports.ILLEGAL_XHR_ERROR = 'Illegal XHR request attempted';

},{}],163:[function(require,module,exports){
'use strict';

module.exports = {
  us: 'en_us',
  gb: 'en_uk',
  uk: 'en_uk',
  de: 'de_de',
  fr: 'fr_fr',
  it: 'it_it',
  es: 'es_es',
  ca: 'en_ca',
  au: 'en_au',
  at: 'de_de',
  be: 'en_us',
  ch: 'de_de',
  dk: 'da_dk',
  nl: 'nl_nl',
  no: 'no_no',
  pl: 'pl_pl',
  se: 'sv_se',
  tr: 'tr_tr',
  bg: 'en_us',
  cy: 'en_us',
  hr: 'en_us',
  is: 'en_us',
  kh: 'en_us',
  mt: 'en_us',
  my: 'en_us',
  ru: 'ru_ru'
};

},{}],164:[function(require,module,exports){
'use strict';

var countryCodeLookupTable = require('../shared/data/country-code-lookup');

function isFormatted(code) {
  return code.indexOf('_') !== -1 && code.length === 5;
}

function queryTable(code) {
  var match;

  for (var key in countryCodeLookupTable) {
    if (countryCodeLookupTable.hasOwnProperty(key)) {
      if (key === code) {
        match = countryCodeLookupTable[key];
      } else if (countryCodeLookupTable[key] === code) {
        match = countryCodeLookupTable[key];
      }
    }
  }

  return match;
}

function getLocale(code) {
  var match;

  code = code ? code.toLowerCase() : 'us';
  code = code.replace(/-/g, '_');

  match = isFormatted(code) ? code : queryTable(code);

  if (match) {
    var pieces = match.split('_');
    return [pieces[0], pieces[1].toUpperCase()].join('_');
  }

  return 'en_US';
}

module.exports = getLocale;

},{"../shared/data/country-code-lookup":163}],165:[function(require,module,exports){
var userAgent = require('./useragent');

var toString = Object.prototype.toString;

function isAndroid() {
  return userAgent.matchUserAgent('Android') && !isChrome();
}

function isChrome() {
  return userAgent.matchUserAgent('Chrome') || userAgent.matchUserAgent('CriOS');
}

function isFirefox() {
  return userAgent.matchUserAgent('Firefox');
}

function isIE() {
  return userAgent.matchUserAgent('Trident') || userAgent.matchUserAgent('MSIE');
}

function isOpera() {
  return userAgent.matchUserAgent('Opera') || userAgent.matchUserAgent('OPR');
}

function isOperaMini() {
  return isOpera() && toString.call(window.operamini) === '[object OperaMini]';
}

function isSafari() {
  return userAgent.matchUserAgent('Safari') && !isChrome() && !isAndroid();
}

module.exports = {
  isAndroid: isAndroid,
  isChrome: isChrome,
  isFirefox: isFirefox,
  isIE: isIE,
  isOpera: isOpera,
  isOperaMini: isOperaMini,
  isSafari: isSafari
};

},{"./useragent":168}],166:[function(require,module,exports){
var userAgent = require('./useragent');
var platform = require('./platform');

function isMobile() {
  return !isTablet() &&
      (platform.isAndroid() || platform.isIpod() || platform.isIphone() ||
       userAgent.matchUserAgent('IEMobile'));
}

function isTablet() {
  return platform.isIpad() || (platform.isAndroid() &&
      !userAgent.matchUserAgent('Mobile'));
}

function isDesktop() {
  return !isMobile() && !isTablet();
}

module.exports = {
  isMobile: isMobile,
  isTablet: isTablet,
  isDesktop: isDesktop
};

},{"./platform":167,"./useragent":168}],167:[function(require,module,exports){
var userAgent = require('./useragent');

function isAndroid() {
  return userAgent.matchUserAgent('Android');
}

function isIpad() {
  return userAgent.matchUserAgent('iPad');
}

function isIpod() {
  return userAgent.matchUserAgent('iPod');
}

function isIphone() {
  return userAgent.matchUserAgent('iPhone') && !isIpod();
}

function isIos() {
  return isIpad() || isIpod() || isIphone();
}

module.exports = {
  isAndroid: isAndroid,
  isIpad: isIpad,
  isIpod: isIpod,
  isIphone: isIphone,
  isIos: isIos
};

},{"./useragent":168}],168:[function(require,module,exports){
var nativeUserAgent = window.navigator.userAgent;

function getNativeUserAgent() {
  return nativeUserAgent;
}

function matchUserAgent(pattern) {
  var userAgent = exports.getNativeUserAgent();
  var matches = userAgent.match(pattern);
  if (matches) {
    return true;
  }
  return false;
}

exports.getNativeUserAgent = getNativeUserAgent;
exports.matchUserAgent = matchUserAgent;

},{}],169:[function(require,module,exports){
var browser = require('../useragent/browser');
var device = require('../useragent/device');
var platform = require('../useragent/platform');
var userAgent = require('../useragent/useragent');

var uaString = window.navigator.userAgent;
var mobileRe = /[Mm]obi|tablet|iOS|Android|IEMobile|Windows\sPhone/;

function isMobile() {
  return isMobileDevice() && window.outerWidth < 600;
}

function isMobileDevice() {
  return mobileRe.test(uaString);
}

function detectedPostMessage() {
  return !!window.postMessage;
}

function isPopupSupported() {
  if (browser.isOperaMini()) {
    return false;
  }

  if (device.isDesktop()) {
    return true;
  }

  if (device.isMobile() || device.isTablet()) {
    if (browser.isIE()) {
      return false;
    }

    if (platform.isAndroid()) {
      return true;
    }

    if (platform.isIos()) {
      // Chrome, Safari Versions 8.0-8.1, or Webviews
      if (browser.isChrome() || (browser.isSafari() && userAgent.matchUserAgent(/OS (?:8_1|8_0|8)(?!_\d)/i)) || !browser.isSafari()) {
        return false;
      } else {
        return true;
      }
    }
  }

  return false;
}

function isOverlaySupported () {
  if (browser.isIE() && userAgent.matchUserAgent(/MSIE 8\.0/)) {
    return false;
  } else {
    try {
      return window.self === window.top;
    } catch (e) {
      return false;
    }
  }
}

function isProxyFrameRequired () {
  return browser.isIE() && !isMetroBrowser();
}

function isMetroBrowser() {
  var supported = null;
  var errorName = '';
  try {
    new ActiveXObject('');
  } catch (e) {
    errorName = e.name;
  }
  try {
    supported = !!new ActiveXObject('htmlfile');
  } catch (e) {
    supported = false;
  }
  if (errorName !== 'ReferenceError' && supported === false) {
    supported = false;
  } else {
    supported = true;
  }
  return !supported;
}

module.exports = {
  isMobile: isMobile,
  isMobileDevice: isMobileDevice,
  detectedPostMessage: detectedPostMessage,
  isPopupSupported: isPopupSupported,
  isOverlaySupported: isOverlaySupported,
  isProxyFrameRequired: isProxyFrameRequired
};

},{"../useragent/browser":165,"../useragent/device":166,"../useragent/platform":167,"../useragent/useragent":168}],170:[function(require,module,exports){
function setTextContent(element, content) {
  var property = 'innerText';
  if (document && document.body) {
    if ('textContent' in document.body) {
      property = 'textContent';
    }
  }
  element[property] = content;
}

module.exports = {
  setTextContent: setTextContent
};

},{}],171:[function(require,module,exports){
var trim = typeof String.prototype.trim === 'function' ?
  function (str) { return str.trim(); } :
  function (str) { return str.replace(/^\s+|\s+$/, ''); };

var btoa = typeof window.btoa === 'function' ?
  function (str) { return window.btoa(str); } :
  function (str) {
    var keyStr =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;

    while (i < str.length) {
      chr1 = str.charCodeAt(i++);
      chr2 = str.charCodeAt(i++);
      chr3 = str.charCodeAt(i++);

      enc1 = chr1 >> 2;
      enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
      enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
      enc4 = chr3 & 63;

      if (isNaN(chr2)) {
        enc3 = enc4 = 64;
      } else if (isNaN(chr3)) {
        enc4 = 64;
      }

      output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) +
          keyStr.charAt(enc3) + keyStr.charAt(enc4);
    }

    return output;
  };

function generateUid() {
  var uid = '';
  for (var i = 0; i < 32; i++) {
    var r = Math.floor(Math.random() * 16);
    uid += r.toString(16);
  }
  return uid;
}

function castToBoolean(value) {
  return /^(true|1)$/i.test(value);
}

function htmlEscape(str) {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\"/g, '&quot;')
            .replace(/\'/g, '&apos;');
}

function parseUrlParams(url) {
  var startIndex = url.indexOf('?');
  var values = {};
  if (startIndex >= 0) {
    url = url.substr(startIndex + 1);
  }
  if (url.length === 0) {
    return;
  }

  var arr = url.split('&');
  for (var i = 0, n = arr.length; i < n; i++) {
    var parts = arr[i];
    var index = parts.indexOf('=');
    var key = parts.substr(0, index);
    var encodedValue = parts.substr(index + 1);
    var value = decodeURIComponent(encodedValue);
    value = value.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    if (value === 'false') {
      value = false;
    }
    if (value === undefined || value === 'true') {
      value = true;
    }
    values[key] = value;
  }

  return values;
}

function isFunction(func) {
  return func && Object.prototype.toString.call(func) === '[object Function]';
}

module.exports = {
  trim: trim,
  btoa: btoa,
  generateUid: generateUid,
  castToBoolean: castToBoolean,
  htmlEscape: htmlEscape,
  parseUrlParams: parseUrlParams,
  isFunction: isFunction
};

},{}],172:[function(require,module,exports){
arguments[4][140][0].apply(exports,arguments)
},{"braintree-utilities":182,"dup":140}],173:[function(require,module,exports){
arguments[4][141][0].apply(exports,arguments)
},{"braintree-utilities":182,"dup":141}],174:[function(require,module,exports){
arguments[4][142][0].apply(exports,arguments)
},{"dup":142}],175:[function(require,module,exports){
arguments[4][143][0].apply(exports,arguments)
},{"braintree-utilities":182,"dup":143}],176:[function(require,module,exports){
arguments[4][144][0].apply(exports,arguments)
},{"braintree-utilities":182,"dup":144}],177:[function(require,module,exports){
arguments[4][145][0].apply(exports,arguments)
},{"./lib/message-bus":172,"./lib/pubsub-client":173,"./lib/pubsub-server":174,"./lib/rpc-client":175,"./lib/rpc-server":176,"dup":145}],178:[function(require,module,exports){
arguments[4][146][0].apply(exports,arguments)
},{"dup":146}],179:[function(require,module,exports){
arguments[4][147][0].apply(exports,arguments)
},{"dup":147}],180:[function(require,module,exports){
arguments[4][148][0].apply(exports,arguments)
},{"dup":148}],181:[function(require,module,exports){
arguments[4][149][0].apply(exports,arguments)
},{"dup":149}],182:[function(require,module,exports){
arguments[4][150][0].apply(exports,arguments)
},{"./lib/dom":178,"./lib/events":179,"./lib/fn":180,"./lib/url":181,"dup":150}],183:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],184:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],185:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],186:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],187:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],188:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":183,"dup":22}],189:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":183,"./lib/dom":184,"./lib/events":185,"./lib/fn":186,"./lib/string":187,"./lib/url":188,"dup":23}],190:[function(require,module,exports){
'use strict';

var RPC_METHOD_NAMES = ['getCreditCards', 'unlockCreditCard', 'sendAnalyticsEvents'];

function APIProxyServer(apiClient) {
  this.apiClient = apiClient;
}

APIProxyServer.prototype.attach = function (rpcServer) {
  var self = this;
  var i = 0;
  var len = RPC_METHOD_NAMES.length;

  function attachDefine(name) {
    rpcServer.define(name, function () {
      self.apiClient[name].apply(self.apiClient, arguments);
    });
  }

  for (i; i < len; i++) {
    attachDefine(RPC_METHOD_NAMES[i]);
  }
};

module.exports = APIProxyServer;

},{}],191:[function(require,module,exports){
'use strict';

var htmlNode, bodyNode;
var api = require('braintree-api');
var bus = require('braintree-bus');
var rpc = require('braintree-rpc');
var utils = require('braintree-utilities');
var APIProxyServer = require('./api-proxy-server');
var MerchantFormManager = require('./merchant-form-manager');
var FrameContainer = require('./frame-container');
var PayPalService = require('../shared/paypal-service');
var constants = require('../shared/constants');
var paypalBrowser = require('braintree-paypal/src/shared/util/browser');
var version = "1.3.10";

function getElementStyle(element, style) {
  var computedStyle = window.getComputedStyle ? getComputedStyle(element) : element.currentStyle;

  return computedStyle[style];
}

function getMerchantPageDefaultStyles() {
  return {
    html: {
      height: htmlNode.style.height || '',
      overflow: getElementStyle(htmlNode, 'overflow'),
      position: getElementStyle(htmlNode, 'position')
    },
    body: {
      height: bodyNode.style.height || '',
      overflow: getElementStyle(bodyNode, 'overflow')
    }
  };
}

function isMobile() {
  var isMobileUserAgent = /Android|iPhone|iPod|iPad/i.test(window.navigator.userAgent);
  return isMobileUserAgent;
}

function Client(settings) {
  var inlineFramePath, modalFramePath, formElement;

  this.encodedClientToken = settings.clientToken;
  this.paypalOptions = settings.paypal;
  this.container = null;
  this.merchantFormManager = null;
  this.root = settings.root;
  this.configurationRequests = [];
  this.braintreeApiClient = api.configure({ clientToken: settings.clientToken, integration: 'dropin' });
  this.paymentMethodNonceReceivedCallback = settings.paymentMethodNonceReceived;
  this.clientToken = api.parseClientToken(settings.clientToken);

  this.bus = new rpc.MessageBus(this.root);
  this.rpcServer = new rpc.RPCServer(this.bus);
  this.apiProxyServer = new APIProxyServer(this.braintreeApiClient);

  this.apiProxyServer.attach(this.rpcServer);

  inlineFramePath = settings.inlineFramePath || this.clientToken.assetsUrl + '/dropin/' + version + '/inline-frame.html';
  modalFramePath = settings.modalFramePath || this.clientToken.assetsUrl + '/dropin/' + version + '/modal-frame.html';
  htmlNode = document.documentElement;
  bodyNode = document.body;

  this.frames = {
    inline: this._createFrame(inlineFramePath, constants.INLINE_FRAME_NAME),
    modal: this._createFrame(modalFramePath, constants.MODAL_FRAME_NAME)
  };

  this.container = utils.normalizeElement(settings.container, 'Unable to find valid container.');

  formElement = utils.normalizeElement(settings.form || this._findClosest(this.container, 'form'));

  this.merchantFormManager = new MerchantFormManager({
    form: formElement,
    frames: this.frames,
    onSubmit: this.paymentMethodNonceReceivedCallback,
    apiClient: this.braintreeApiClient
  }).initialize();

  if (this.clientToken.paypalEnabled && (this.clientToken.paypal && (utils.isBrowserHttps() || this.clientToken.paypal.allowHttp))) {
    this._configurePayPal();
  }

  this.braintreeApiClient.sendAnalyticsEvents('dropin.web.initialized');
}

Client.prototype.initialize = function () {
  var i;
  var self = this;

  this._initializeModal();

  bus.emit(bus.events.ASYNC_DEPENDENCY_INITIALIZING);
  this.container.appendChild(this.frames.inline.element);
  bodyNode.appendChild(this.frames.modal.element);

  this.rpcServer.define('receiveSharedCustomerIdentifier', function (sharedCustomerIdentifier) {
    self.braintreeApiClient.attrs.sharedCustomerIdentifier = sharedCustomerIdentifier;
    self.braintreeApiClient.attrs.sharedCustomerIdentifierType = 'browser_session_cookie_store';

    for (i = 0; i < self.configurationRequests.length; i++) {
      self.configurationRequests[i](self.encodedClientToken);
    }

    self.configurationRequests = [];
  });

  bus.on(bus.events.PAYMENT_METHOD_GENERATED, utils.bind(this._handleAltPayData, this));

  this.rpcServer.define('getConfiguration', function (reply) {
    reply({
      clientToken: self.encodedClientToken,
      merchantHttps: utils.isBrowserHttps()
    });
  });

  this.rpcServer.define('getPayPalOptions', function (reply) {
    reply(self.paypalOptions);
  });

  this.rpcServer.define('selectPaymentMethod', function (paymentMethods) {
    self.frames.modal.rpcClient.invoke('selectPaymentMethod', [paymentMethods]);
    self._showModal();
  });

  this.rpcServer.define('sendAddedPaymentMethod', function (paymentMethod) {
    self.merchantFormManager.setNoncePayload(paymentMethod);

    self.frames.inline.rpcClient.invoke('receiveNewPaymentMethod', [paymentMethod]);
  });

  this.rpcServer.define('sendUsedPaymentMethod', function (paymentMethod) {
    self.frames.inline.rpcClient.invoke('selectPaymentMethod', [paymentMethod]);
  });

  this.rpcServer.define('sendUnlockedNonce', function (paymentMethod) {
    self.merchantFormManager.setNoncePayload(paymentMethod);
  });

  this.rpcServer.define('clearNonce', function () {
    self.merchantFormManager.clearNoncePayload();
  });

  this.rpcServer.define('closeDropInModal', function () {
    self._hideModal();
  });

  this.rpcServer.define('setInlineFrameHeight', function (height) {
    self.frames.inline.element.style.height = height + 'px';
  });

  this.bus.register('ready', function (message) {
    if (message.source === self.frames.inline.element.contentWindow) {
      self.frames.inline.rpcClient = new rpc.RPCClient(self.bus, message.source);
    } else if (message.source === self.frames.modal.element.contentWindow) {
      self.frames.modal.rpcClient = new rpc.RPCClient(self.bus, message.source);
    }
  });
};

Client.prototype._createFrame = function (endpoint, name) {
  return new FrameContainer(endpoint, name);
};

Client.prototype._initializeModal = function () {
  this.frames.modal.element.style.display = 'none';
  this.frames.modal.element.style.position = isMobile() ? 'absolute' : 'fixed';
  this.frames.modal.element.style.top = '0';
  this.frames.modal.element.style.left = '0';
  this.frames.modal.element.style.height = '100%';
  this.frames.modal.element.style.width = '100%';
};

Client.prototype._lockMerchantWindowSize = function () {
  setTimeout(function () {
    htmlNode.style.overflow = 'hidden';
    bodyNode.style.overflow = 'hidden';
    bodyNode.style.height = '100%';

    if (isMobile()) {
      htmlNode.style.position = 'relative';
      htmlNode.style.height = window.innerHeight + 'px';
    }
  }, 160);
};

Client.prototype._unlockMerchantWindowSize = function () {
  var defaultStyles = this.merchantPageDefaultStyles;

  bodyNode.style.height = defaultStyles.body.height;
  bodyNode.style.overflow = defaultStyles.body.overflow;

  htmlNode.style.overflow = defaultStyles.html.overflow;

  if (isMobile()) {
    htmlNode.style.height = defaultStyles.html.height;
    htmlNode.style.position = defaultStyles.html.position;
  }
};

Client.prototype._showModal = function () {
  var self = this;
  var el = this.frames.modal.element;

  this.merchantPageDefaultStyles = getMerchantPageDefaultStyles();

  el.style.display = 'block';

  this.frames.modal.rpcClient.invoke('open', [], function () {
    setTimeout(function () {
      self._lockMerchantWindowSize();
      el.contentWindow.focus();
    }, 200);
  });
};

Client.prototype._hideModal = function () {
  this._unlockMerchantWindowSize();
  this.frames.modal.element.style.display = 'none';
};

Client.prototype._configurePayPal = function () {
  if (!paypalBrowser.isPopupSupported()) {
    this.ppClient = new PayPalService({
      clientToken: this.clientToken,
      paypal: this.paypalOptions
    });

    this.rpcServer.define('openPayPalModal', utils.bind(this.ppClient._openModal, this.ppClient));
  }

  this.rpcServer.define('receivePayPalData', utils.bind(this._handleAltPayData, this));
};

Client.prototype._handleAltPayData = function (payload) {
  this.merchantFormManager.setNoncePayload(payload);
  this.frames.inline.rpcClient.invoke('receiveNewPaymentMethod', [payload]);
  this.frames.modal.rpcClient.invoke('modalViewClose');
};

Client.prototype._findClosest = function (node, tagName) {
  tagName = tagName.toUpperCase();

  do {
    if (node.nodeName === tagName) {
      return node;
    }
  } while (node = node.parentNode);

  throw 'Unable to find a valid ' + tagName;
};

module.exports = Client;

},{"../shared/constants":195,"../shared/paypal-service":196,"./api-proxy-server":190,"./frame-container":193,"./merchant-form-manager":194,"braintree-api":77,"braintree-bus":100,"braintree-paypal/src/shared/util/browser":169,"braintree-rpc":177,"braintree-utilities":189}],192:[function(require,module,exports){
'use strict';

var Client = require('./client');
var VERSION = "1.3.10";

function create(clientToken, options) {
  var client;

  options.clientToken = clientToken;
  client = new Client(options);
  client.initialize();

  return client;
}

module.exports = {
  create: create,
  VERSION: VERSION
};

},{"./client":191}],193:[function(require,module,exports){
'use strict';

var bus = require('braintree-bus');
var constants = require('../shared/constants');

// TODO: move to shared and deduplicate from src/internal/util/dropin-util.js
var TRANSITION_END_EVENT_NAMES = {
  transition: 'transitionend',
  '-o-transition': 'otransitionEnd',
  '-moz-transition': 'transitionend',
  '-webkit-transition': 'webkitTransitionEnd'
};

function getTransitionEndEventName() {
  var eventName;
  var fakeEl = document.createElement('fakeelement');

  for (eventName in TRANSITION_END_EVENT_NAMES) {
    if (typeof fakeEl.style[eventName] !== 'undefined') {
      return TRANSITION_END_EVENT_NAMES[eventName];
    }
  }
  return null;
}

function listenForReady(el) {
  var transitionEndEvent = getTransitionEndEventName();

  function handler(event) {
    if (event.target === el && event.propertyName === 'height') {
      bus.emit(bus.events.ASYNC_DEPENDENCY_READY);
      el.removeEventListener(transitionEndEvent, handler);
    }
  }

  if (transitionEndEvent) {
    el.addEventListener(transitionEndEvent, handler);
  } else {
    setTimeout(function () {
      bus.emit(bus.events.ASYNC_DEPENDENCY_READY);
    }, 500);
  }
}

function FrameContainer(endpoint, name) {
  this.element = document.createElement('iframe');
  this.element.setAttribute('name', name);
  this.element.setAttribute('allowtransparency', 'true');
  this.element.setAttribute('width', '100%');
  this.element.setAttribute('height', '68');
  this.element.setAttribute('style', '-webkit-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); -moz-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); -ms-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); -o-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000);');
  this.element.src = endpoint;

  this.element.setAttribute('frameborder', '0');
  this.element.setAttribute('allowtransparency', 'true');
  this.element.style.border = '0';
  this.element.style.zIndex = '9999';

  if (name === constants.INLINE_FRAME_NAME) {
    listenForReady(this.element);
  }
}

module.exports = FrameContainer;

},{"../shared/constants":195,"braintree-bus":100}],194:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function MerchantFormManager(options) {
  this.form = options.form;
  this.frames = options.frames;
  this.onSubmit = options.onSubmit;
  this.apiClient = options.apiClient;
}

MerchantFormManager.prototype.initialize = function () {
  if (this._isSubmitBased()) {
    this._setElements();
  }

  this._setEvents();

  return this;
};

MerchantFormManager.prototype.setNoncePayload = function (payload) {
  this.noncePayload = payload;
};

MerchantFormManager.prototype.clearNoncePayload = function () {
  this.noncePayload = null;
};

MerchantFormManager.prototype._isSubmitBased = function () {
  return !this.onSubmit;
};

MerchantFormManager.prototype._isCallbackBased = function () {
  return !!this.onSubmit;
};

MerchantFormManager.prototype._setElements = function () {
  var input;

  if (!this.form.payment_method_nonce) {
    input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'payment_method_nonce';
    this.form.appendChild(input);
  }

  this.nonceField = this.form.payment_method_nonce;
};

MerchantFormManager.prototype._setEvents = function () {
  var self = this;

  utils.addEventListener(this.form, 'submit', function () {
    self._handleFormSubmit.apply(self, arguments);
  });
};

MerchantFormManager.prototype._handleFormSubmit = function (event) {
  if (this._shouldSubmit()) { return; }

  if (event && event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  if (this.noncePayload && this.noncePayload.nonce) {
    this._handleNonceReply(event);
  } else {
    this.frames.inline.rpcClient.invoke('requestNonce', [], utils.bind(function (payload) {
      this.setNoncePayload(payload);
      this._handleNonceReply(event);
    }, this));
  }
};

MerchantFormManager.prototype._shouldSubmit = function () {
  return this._isCallbackBased() ? false : this.nonceField.value.length > 0;
};

MerchantFormManager.prototype._handleNonceReply = function (event) {
  if (this._isCallbackBased()) {
    this.apiClient.sendAnalyticsEvents('dropin.web.end.callback', utils.bind(function () {
      var payload = this.noncePayload;

      payload.originalEvent = event;

      this.onSubmit(payload);

      setTimeout(utils.bind(function () {
        this.frames.inline.rpcClient.invoke('clearLoadingState');
      }, this), 200);
    }, this));
  } else {
    this._triggerFormSubmission();
  }
};

MerchantFormManager.prototype._triggerFormSubmission = function () {
  this.nonceField.value = this.noncePayload.nonce;

  this.apiClient.sendAnalyticsEvents('dropin.web.end.auto-submit', utils.bind(function () {
    if (typeof this.form.submit === 'function') {
      this.form.submit();
    } else {
      this.form.querySelector('[type="submit"]').click();
    }
  }, this));
};

module.exports = MerchantFormManager;

},{"braintree-utilities":189}],195:[function(require,module,exports){
'use strict';

module.exports = {
  PAYPAL_INTEGRATION_NAME: 'PayPal',
  INLINE_FRAME_NAME: 'braintree-dropin-frame',
  MODAL_FRAME_NAME: 'braintree-dropin-modal-frame',
  PAYMENT_METHOD_TYPES: ['CoinbaseAccount', 'PayPalAccount', 'CreditCard']
};

},{}],196:[function(require,module,exports){
'use strict';

var PaypalClient = require('braintree-paypal/src/external/client');

function PayPalService(options) {
  var clientToken = options.clientToken;
  var paypalOptions = options.paypal || {};

  var client = new PaypalClient(clientToken, {
    container: document.createElement('div'),
    displayName: paypalOptions.displayName,
    locale: paypalOptions.locale,
    singleUse: paypalOptions.singleUse,
    amount: paypalOptions.amount,
    currency: paypalOptions.currency,
    onSuccess: paypalOptions.onSuccess,
    enableShippingAddress: paypalOptions.enableShippingAddress,
    shippingAddressOverride: paypalOptions.shippingAddressOverride
  });

  client.initialize();

  return client;
}

module.exports = PayPalService;

},{"braintree-paypal/src/external/client":158}],197:[function(require,module,exports){
(function (global){
'use strict';
var ELEMENT_NODE = global.Node ? global.Node.ELEMENT_NODE : 1;

function extractValues(node, results) {
  results = results || {};

  var child, i;
  var children = node.children;

  for (i = 0; i < children.length; i++) {
    child = children[i];

    if (isBraintreeNode(child)) {
      var dataAttr = child.getAttribute('data-braintree-name');

      if (dataAttr === 'postal_code') {
        results.billingAddress = {
          postalCode: child.value
        };
      } else {
        results[dataAttr] = child.value;
      }

      scrubAttributes(child);
    } else if (child.children && child.children.length > 0) {
      extractValues(child, results);
    }
  }

  return results;
}

function scrubAttributes(node) {
  try {
    node.attributes.removeNamedItem('name');
  } catch (e) {}
}

function scrubAllAttributes(node) {
  extractValues(node);
}

function isBraintreeNode(node) {
  return node.nodeType === ELEMENT_NODE && node.attributes['data-braintree-name'];
}

module.exports = {
  extractValues: extractValues,
  scrubAllAttributes: scrubAllAttributes,
  scrubAttributes: scrubAttributes,
  isBraintreeNode: isBraintreeNode
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],198:[function(require,module,exports){
'use strict';

var util = require('braintree-utilities');
var fields = require('./fields');
var bus = require('braintree-bus');
var PaymentMethodModel = require('./models/payment-method-model');
var ERROR_PAYLOAD = {
  message: 'Unable to process payments at this time',
  type: 'IMMEDIATE'
};

function Form(client, htmlForm, nonceInput, isCreditCardForm) {
  this.client = client;
  this.htmlForm = htmlForm;
  this.isCreditCardForm = isCreditCardForm === false ? false : true;
  this.paymentMethodNonceInput = nonceInput;
  this.model = new PaymentMethodModel();
  this.setEvents();
}

Form.prototype.setEvents = function () {
  this.onSubmitHandler = util.bind(this.handleSubmit, this);
  this.onExternalNonceReceived = util.bind(this.onExternalNonceReceived, this);
  this.clearExternalNonce = util.bind(this.clearExternalNonce, this);

  util.addEventListener(this.htmlForm, 'submit', this.onSubmitHandler);
  bus.on(bus.events.PAYMENT_METHOD_GENERATED, this.onExternalNonceReceived);
  bus.on(bus.events.PAYMENT_METHOD_CANCELLED, this.clearExternalNonce);
};

Form.prototype.handleSubmit = function (event) {
  var type;

  if (event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  if (!this.isCreditCardForm) {
    this.onNonceReceived(null, this.model.attributes);
    return;
  }

  type = this.model.get('type');

  if (type && type !== 'CreditCard') {
    fields.scrubAllAttributes(this.htmlForm);
    this.onNonceReceived(null, this.model.attributes);
    return;
  }

  this.client.tokenizeCard(fields.extractValues(this.htmlForm), util.bind(function (err, nonce, payload) {
    if (err) {
      this.onNonceReceived(ERROR_PAYLOAD, null);
    } else {
      this.model.set({
        nonce: nonce,
        type: payload.type,
        details: payload.details
      });

      this.onNonceReceived(null, this.model.attributes);
    }
  }, this));
};

Form.prototype.writeNonceToDOM = function () {
  this.paymentMethodNonceInput.value = this.model.get('nonce');
};

Form.prototype.onExternalNonceReceived = function (payload) {
  this.model.set(payload);
};

Form.prototype.clearExternalNonce = function () {
  this.model.reset();
};

Form.prototype.onNonceReceived = function (err) {
  var form = this.htmlForm;

  if (err) {
    bus.emit(bus.events.ERROR, ERROR_PAYLOAD);
    return;
  }

  util.removeEventListener(form, 'submit', this.onSubmitHandler);

  this.writeNonceToDOM();

  if (form.submit && (typeof form.submit === 'function' || form.submit.call)) {
    form.submit();
  } else {
    setTimeout(function () {
      form.querySelector('[type="submit"]').click();
    }, 1);
  }
};

module.exports = Form;

},{"./fields":197,"./models/payment-method-model":200,"braintree-bus":203,"braintree-utilities":212}],199:[function(require,module,exports){
'use strict';

module.exports = function getNonceInput(paymentMethodNonceInputField) {
  var nonceInputName;

  if (typeof paymentMethodNonceInputField === 'object') {
    return paymentMethodNonceInputField;
  }

  nonceInputName = 'payment_method_nonce';

  if (typeof paymentMethodNonceInputField === 'string') {
    nonceInputName = paymentMethodNonceInputField;
  }

  var nonceInput = document.createElement('input');
  nonceInput.name = nonceInputName;
  nonceInput.type = 'hidden';

  return nonceInput;
};

},{}],200:[function(require,module,exports){
'use strict';

function PaymentMethodModel() {
  this.reset();
}

PaymentMethodModel.prototype.get = function (key) {
  return this.attributes[key];
}

PaymentMethodModel.prototype.set = function (payload) {
  this.attributes = payload || {};
};

PaymentMethodModel.prototype.reset = function () {
  this.attributes = {};
}

module.exports = PaymentMethodModel;

},{}],201:[function(require,module,exports){
'use strict';

module.exports = function validateAnnotations(htmlForm) {
  var inputs = htmlForm.getElementsByTagName('*');
  var valid = {};

  for (var i = 0; i < inputs.length; i++) {
    var field = inputs[i].getAttribute('data-braintree-name');
    valid[field] = true;
  }

  if (!valid.number) {
    throw new Error('Unable to find an input with data-braintree-name="number" in your form. Please add one.');
  }

  if (valid.expiration_date) {
    if (valid.expiration_month || valid.expiration_year) {
      throw new Error('You have inputs with data-braintree-name="expiration_date" AND data-braintree-name="expiration_(year|month)". Please use either "expiration_date" or "expiration_year" and "expiration_month".');
    }
  } else {
    if (!valid.expiration_month && !valid.expiration_year) {
      throw new Error('Unable to find an input with data-braintree-name="expiration_date" in your form. Please add one.');
    }

    if (!valid.expiration_month) {
      throw new Error('Unable to find an input with data-braintree-name="expiration_month" in your form. Please add one.');
    }

    if (!valid.expiration_year) {
      throw new Error('Unable to find an input with data-braintree-name="expiration_year" in your form. Please add one.');
    }
  }
};

},{}],202:[function(require,module,exports){
'use strict';

var Form = require('./lib/form');
var validateAnnotations = require('./lib/validate-annotations');
var getNonceInput = require('./lib/get-nonce-input');

function setup(client, options) {
  var nonceInput, form;
  var htmlForm = document.getElementById(options.id);
  var isCreditCardForm = options && options.hasOwnProperty('useCreditCard') ? options.useCreditCard : true;

  if (!htmlForm) {
    throw new Error('Unable to find form with id: "' + options.id + '"');
  }

  if (isCreditCardForm) {
    validateAnnotations(htmlForm);
  }

  nonceInput = getNonceInput(options.paymentMethodNonceInputField);
  htmlForm.appendChild(nonceInput);

  form = new Form(client, htmlForm, nonceInput, isCreditCardForm);

  return form;
}

module.exports = {setup: setup};

},{"./lib/form":198,"./lib/get-nonce-input":199,"./lib/validate-annotations":201}],203:[function(require,module,exports){
arguments[4][39][0].apply(exports,arguments)
},{"./lib/events":204,"dup":39,"framebus":205}],204:[function(require,module,exports){
arguments[4][40][0].apply(exports,arguments)
},{"dup":40}],205:[function(require,module,exports){
arguments[4][41][0].apply(exports,arguments)
},{"dup":41}],206:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],207:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],208:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],209:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],210:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],211:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":206,"dup":22}],212:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":206,"./lib/dom":207,"./lib/events":208,"./lib/fn":209,"./lib/string":210,"./lib/url":211,"dup":23}],213:[function(require,module,exports){
arguments[4][2][0].apply(exports,arguments)
},{"./coinbase-account":214,"./credit-card":215,"./europe-bank-account":216,"./normalize-api-fields":220,"./parse-client-token":221,"./paypal-account":222,"./request-driver":224,"./sepa-mandate":225,"./util":226,"braintree-3ds":237,"braintree-utilities":249,"dup":2}],214:[function(require,module,exports){
arguments[4][3][0].apply(exports,arguments)
},{"dup":3}],215:[function(require,module,exports){
arguments[4][4][0].apply(exports,arguments)
},{"dup":4}],216:[function(require,module,exports){
arguments[4][5][0].apply(exports,arguments)
},{"dup":5}],217:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./parse-client-token":221,"./request-driver":224,"./util":226,"dup":6}],218:[function(require,module,exports){
arguments[4][7][0].apply(exports,arguments)
},{"./jsonp":219,"dup":7}],219:[function(require,module,exports){
arguments[4][8][0].apply(exports,arguments)
},{"./util":226,"dup":8}],220:[function(require,module,exports){
arguments[4][9][0].apply(exports,arguments)
},{"dup":9}],221:[function(require,module,exports){
arguments[4][10][0].apply(exports,arguments)
},{"./polyfill":223,"braintree-utilities":249,"dup":10}],222:[function(require,module,exports){
arguments[4][11][0].apply(exports,arguments)
},{"dup":11}],223:[function(require,module,exports){
arguments[4][12][0].apply(exports,arguments)
},{"dup":12}],224:[function(require,module,exports){
arguments[4][13][0].apply(exports,arguments)
},{"./jsonp-driver":218,"dup":13}],225:[function(require,module,exports){
arguments[4][14][0].apply(exports,arguments)
},{"dup":14}],226:[function(require,module,exports){
arguments[4][15][0].apply(exports,arguments)
},{"dup":15}],227:[function(require,module,exports){
arguments[4][16][0].apply(exports,arguments)
},{"./lib/client":213,"./lib/get-configuration":217,"./lib/jsonp":219,"./lib/jsonp-driver":218,"./lib/parse-client-token":221,"./lib/util":226,"dup":16}],228:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],229:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],230:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],231:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],232:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],233:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":228,"dup":22}],234:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":228,"./lib/dom":229,"./lib/events":230,"./lib/fn":231,"./lib/string":232,"./lib/url":233,"dup":23}],235:[function(require,module,exports){
arguments[4][24][0].apply(exports,arguments)
},{"../shared/receiver":242,"braintree-utilities":234,"dup":24}],236:[function(require,module,exports){
arguments[4][25][0].apply(exports,arguments)
},{"./authorization_service":235,"./loader":238,"braintree-utilities":234,"dup":25}],237:[function(require,module,exports){
arguments[4][26][0].apply(exports,arguments)
},{"./client":236,"dup":26}],238:[function(require,module,exports){
arguments[4][27][0].apply(exports,arguments)
},{"./loader_display":239,"./loader_message":240,"./loader_spinner":241,"dup":27}],239:[function(require,module,exports){
arguments[4][28][0].apply(exports,arguments)
},{"dup":28}],240:[function(require,module,exports){
arguments[4][29][0].apply(exports,arguments)
},{"dup":29}],241:[function(require,module,exports){
arguments[4][30][0].apply(exports,arguments)
},{"dup":30}],242:[function(require,module,exports){
arguments[4][31][0].apply(exports,arguments)
},{"braintree-utilities":234,"dup":31}],243:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],244:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],245:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],246:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],247:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],248:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":243,"dup":22}],249:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":243,"./lib/dom":244,"./lib/events":245,"./lib/fn":246,"./lib/string":247,"./lib/url":248,"dup":23}],250:[function(require,module,exports){
arguments[4][140][0].apply(exports,arguments)
},{"braintree-utilities":260,"dup":140}],251:[function(require,module,exports){
arguments[4][141][0].apply(exports,arguments)
},{"braintree-utilities":260,"dup":141}],252:[function(require,module,exports){
arguments[4][142][0].apply(exports,arguments)
},{"dup":142}],253:[function(require,module,exports){
arguments[4][143][0].apply(exports,arguments)
},{"braintree-utilities":260,"dup":143}],254:[function(require,module,exports){
arguments[4][144][0].apply(exports,arguments)
},{"braintree-utilities":260,"dup":144}],255:[function(require,module,exports){
arguments[4][145][0].apply(exports,arguments)
},{"./lib/message-bus":250,"./lib/pubsub-client":251,"./lib/pubsub-server":252,"./lib/rpc-client":253,"./lib/rpc-server":254,"dup":145}],256:[function(require,module,exports){
arguments[4][146][0].apply(exports,arguments)
},{"dup":146}],257:[function(require,module,exports){
arguments[4][147][0].apply(exports,arguments)
},{"dup":147}],258:[function(require,module,exports){
arguments[4][148][0].apply(exports,arguments)
},{"dup":148}],259:[function(require,module,exports){
arguments[4][149][0].apply(exports,arguments)
},{"dup":149}],260:[function(require,module,exports){
arguments[4][150][0].apply(exports,arguments)
},{"./lib/dom":256,"./lib/events":257,"./lib/fn":258,"./lib/url":259,"dup":150}],261:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],262:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],263:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],264:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],265:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],266:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":261,"dup":22}],267:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":261,"./lib/dom":262,"./lib/events":263,"./lib/fn":264,"./lib/string":265,"./lib/url":266,"dup":23}],268:[function(require,module,exports){
arguments[4][158][0].apply(exports,arguments)
},{"../shared/constants":273,"../shared/get-locale":275,"../shared/util/browser":280,"../shared/util/dom":281,"../shared/util/util":282,"./logged-in-view":270,"./logged-out-view":271,"./overlay-view":272,"braintree-api":227,"braintree-rpc":255,"braintree-utilities":267,"dup":158}],269:[function(require,module,exports){
var Client = require('./client');
var browser = require('../shared/util/browser');
var VERSION = "1.3.5";

function create(clientToken, options) {
  if (!browser.detectedPostMessage()) {
    if (typeof options.onUnsupported === 'function') {
      options.onUnsupported(new Error('unsupported browser detected'));
    }
    return;
  }
  var client = new Client(clientToken, options);
  client.initialize();
  return client;
}

module.exports = {
  create: create,
  _browser: browser,
  VERSION: VERSION
};

},{"../shared/util/browser":280,"./client":268}],270:[function(require,module,exports){
arguments[4][159][0].apply(exports,arguments)
},{"../shared/constants":273,"dup":159}],271:[function(require,module,exports){
arguments[4][160][0].apply(exports,arguments)
},{"../shared/constants":273,"../shared/get-locale":275,"braintree-utilities":267,"dup":160}],272:[function(require,module,exports){
arguments[4][161][0].apply(exports,arguments)
},{"../shared/constants":273,"braintree-utilities":267,"dup":161}],273:[function(require,module,exports){
arguments[4][162][0].apply(exports,arguments)
},{"dup":162}],274:[function(require,module,exports){
arguments[4][163][0].apply(exports,arguments)
},{"dup":163}],275:[function(require,module,exports){
arguments[4][164][0].apply(exports,arguments)
},{"../shared/data/country-code-lookup":274,"dup":164}],276:[function(require,module,exports){
arguments[4][165][0].apply(exports,arguments)
},{"./useragent":279,"dup":165}],277:[function(require,module,exports){
arguments[4][166][0].apply(exports,arguments)
},{"./platform":278,"./useragent":279,"dup":166}],278:[function(require,module,exports){
arguments[4][167][0].apply(exports,arguments)
},{"./useragent":279,"dup":167}],279:[function(require,module,exports){
arguments[4][168][0].apply(exports,arguments)
},{"dup":168}],280:[function(require,module,exports){
arguments[4][169][0].apply(exports,arguments)
},{"../useragent/browser":276,"../useragent/device":277,"../useragent/platform":278,"../useragent/useragent":279,"dup":169}],281:[function(require,module,exports){
arguments[4][170][0].apply(exports,arguments)
},{"dup":170}],282:[function(require,module,exports){
arguments[4][171][0].apply(exports,arguments)
},{"dup":171}],283:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],284:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],285:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],286:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],287:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],288:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":283,"dup":22}],289:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":283,"./lib/dom":284,"./lib/events":285,"./lib/fn":286,"./lib/string":287,"./lib/url":288,"dup":23}],290:[function(require,module,exports){
(function (global){
'use strict';

function FormNapper(form) {
  if (typeof form === 'string' || form instanceof String) {
    form = document.getElementById(form);
  }

  if (form instanceof HTMLFormElement) {
    this.htmlForm = form;
  } else {
    throw new TypeError('FormNapper requires an HTMLFormElement element or the id string of one.');
  }
}

FormNapper.prototype.hijack = function (onsubmit) {
  function handler(event) {
    if (event.preventDefault) {
      event.preventDefault();
    } else {
      event.returnValue = false;
    }

    onsubmit(event);
  }

  if (global.addEventListener != null) {
    this.htmlForm.addEventListener('submit', handler, false);
  } else if (global.attachEvent != null) {
    this.htmlForm.attachEvent('onsubmit', handler);
  } else {
    this.htmlForm.onsubmit = handler;
  }
};

FormNapper.prototype.inject = function (name, value) {
  var input = this.htmlForm.querySelector('input[name="' + name + '"]');

  if (input == null) {
    input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    this.htmlForm.appendChild(input);
  }

  input.value = value;
};

FormNapper.prototype.submit = function () {
  HTMLFormElement.prototype.submit.call(this.htmlForm);
};

module.exports = FormNapper;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],291:[function(require,module,exports){
var hostedFields = require('./lib/external');
var events = require('./lib/shared/constants').events;
var VERSION = "0.2.0";

module.exports = {
  setup: hostedFields.setup,
  events: events,
  VERSION: VERSION
};

},{"./lib/external":293,"./lib/shared/constants":295}],292:[function(require,module,exports){
var constants = require('../shared/constants');

module.exports = function composeUrl(configuration) {
  return configuration.assetsUrl + '/hosted-fields/' + constants.VERSION + '/hosted-fields-frame.html';
};

},{"../shared/constants":295}],293:[function(require,module,exports){
'use strict';

var classListManager = require('classlist');
var iFramer = require('iframer');
var bus = require('braintree-bus');
var composeUrl = require('./compose-url');
var constants = require('../shared/constants');
var nodeListToArray = require('nodelist-to-array');
var utils = require('braintree-utilities');
var findParentTags = require('../shared/find-parent-tags');
var shouldUseLabelFocus = require('./should-use-label-focus');
var events = constants.events;

function injectFrame(frame, container) {
  var clearboth = document.createElement('div');

  clearboth.style.clear = 'both';

  container = container || document.body;

  container.appendChild(frame);
  container.appendChild(clearboth);
}

function setupLabelFocus(type, container) {
  var labels, i;

  if (!shouldUseLabelFocus()) { return; }
  if (container.id == null) { return; }

  function triggerFocus() {
    bus.emit(events.TRIGGER_INPUT_FOCUS, type);
  }

  labels = nodeListToArray(document.querySelectorAll('label[for="' + container.id + '"]'));
  labels = labels.concat(findParentTags(container, 'label'));

  for (i = 0; i < labels.length; i++) {
    utils.addEventListener(labels[i], 'click', triggerFocus, false);
  }
}

function setup(options) {
  var type, field, container, frame, i, msg;
  var fields = {};
  var fieldCount = 0;

  bus.emit(bus.events.ASYNC_DEPENDENCY_INITIALIZING);
  bus.emit(bus.events.SEND_ANALYTICS_EVENTS, 'hosted-fields.initialized');

  if (!options || options.hostedFields == null) {
    bus.emit(bus.events.ERROR, {
      type: 'CONFIGURATION',
      message: 'options.hostedFields is required'
    });
    return null;
  }

  for (i = 0; i < constants.whitelistedFields.length; i++) {
    type = constants.whitelistedFields[i];
    field = options.hostedFields[type];

    if (!field) { continue; }

    container = document.querySelector(field.selector);

    if (!container) {
      msg = 'Unable to find element with selector "' + field.selector + '" for hostedFields.' + type;
      bus.emit(bus.events.ERROR, {
        message: msg
      });
      continue;
    } else if (container.querySelector('iframe[name^="braintree-"]')) {
      bus.emit(bus.events.ERROR, {
        message: 'Cannot place two elements in "' + field.selector + '"'
      });
      continue;
    }

    frame = iFramer({
      type: type,
      name: 'braintree-hosted-field-' + type,
      src: composeUrl(options.configuration),
      style: constants.defaultIFrameStyle
    });
    injectFrame(frame, container);

    setupLabelFocus(type, container);

    fields[type] = {
      frameElement: frame,
      containerElement: container
    };
    fieldCount++;
  }

  bus.on(events.FRAME_READY, function (reply) {
    fieldCount--;
    if (fieldCount === 0) {
      reply(true);
    } else {
      reply(false);
    }
  });

  bus.on(events.INPUT_EVENT, inputEventHandler(fields, options));

  return fields;
}

function inputEventHandler(fields, options) {
  return function (eventData) {
    var container = fields[eventData.fieldKey].containerElement;
    var handler = options.hostedFields.onFieldEvent;
    var classList = classListManager(container);

    eventData.target = {
      fieldKey: eventData.fieldKey,
      container: container
    };

    classList
      .toggle(constants.externalClasses.FOCUSED, eventData.isFocused)
      .toggle(constants.externalClasses.VALID, eventData.isValid);
    if (eventData.isStrictlyValidating) {
      classList.toggle(constants.externalClasses.INVALID, !eventData.isValid);
    } else {
      classList.toggle(constants.externalClasses.INVALID, !eventData.isPotentiallyValid);
    }

    delete eventData.fieldKey;
    delete eventData.isStrictlyValidating;

    if (handler) {
      handler(eventData);
    }
  };
}

module.exports = {
  injectFrame: injectFrame,
  setup: setup
};

},{"../shared/constants":295,"../shared/find-parent-tags":296,"./compose-url":292,"./should-use-label-focus":294,"braintree-bus":297,"braintree-utilities":306,"classlist":307,"iframer":310,"nodelist-to-array":324}],294:[function(require,module,exports){
'use strict';

module.exports = function shouldUseLabelFocus() {
  return !/(iPad|iPhone|iPod)/i.test(navigator.userAgent);
};

},{}],295:[function(require,module,exports){
/*eslint-disable no-reserved-keys */
'use strict';

var VERSION = "0.2.0";

module.exports = {
  VERSION: VERSION,
  events: {
    FRAME_READY: 'hosted-fields:FRAME_READY',
    VALIDATE_STRICT: 'hosted-fields:VALIDATE_STRICT',
    CONFIGURATION: 'hosted-fields:CONFIGURATION',
    TOKENIZATION_REQUEST: 'hosted-fields:TOKENIZATION_REQUEST',
    INPUT_EVENT: 'hosted-fields:INPUT_EVENT',
    TRIGGER_INPUT_FOCUS: 'hosted-fields:TRIGGER_INPUT_FOCUS'
  },
  externalEvents: {
    FOCUS: 'focus',
    BLUR: 'blur',
    FIELD_STATE_CHANGE: 'fieldStateChange'
  },
  defaultMaxLengths: {
    number: 19,
    postalCode: 8,
    expirationDate: 7,
    expirationMonth: 2,
    expirationYear: 4,
    cvv: 3
  },
  externalClasses: {
    FOCUSED: 'braintree-hosted-fields-focused',
    INVALID: 'braintree-hosted-fields-invalid',
    VALID: 'braintree-hosted-fields-valid'
  },
  defaultIFrameStyle: {
    border: 'none',
    width: '100%',
    height: '100%',
    float: 'left'
  },
  whitelistedFields: [
    'number',
    'cvv',
    'expirationDate',
    'expirationMonth',
    'expirationYear',
    'postalCode'
  ],
  whitelistedStyles: [
    '-moz-osx-font-smoothing',
    '-moz-transition',
    '-webkit-font-smoothing',
    '-webkit-transition',
    'color',
    'font',
    'font-family',
    'font-size',
    'font-size-adjust',
    'font-stretch',
    'font-style',
    'font-variant',
    'font-variant-alternates',
    'font-variant-caps',
    'font-variant-east-asian',
    'font-variant-ligatures',
    'font-variant-numeric',
    'font-weight',
    'line-height',
    'opacity',
    'outline',
    'text-shadow',
    'transition'
  ],
  passwordManagerFields: {
    number: {
      name: 'credit-card-number',
      label: 'Credit Card Number'
    },
    expirationDate: {
      name: 'expiration',
      label: 'Expiration Date'
    },
    postalCode: {
      name: 'postal-code',
      label: 'Postal Code'
    }
  }
};

},{}],296:[function(require,module,exports){
'use strict';

function findParentTags(element, tag) {
  var parent = element.parentNode;
  var parents = [];

  while (parent != null) {
    if (parent.tagName != null && parent.tagName.toLowerCase() === tag) {
      parents.push(parent);
    }

    parent = parent.parentNode;
  }

  return parents;
}

module.exports = findParentTags;

},{}],297:[function(require,module,exports){
arguments[4][39][0].apply(exports,arguments)
},{"./lib/events":298,"dup":39,"framebus":299}],298:[function(require,module,exports){
arguments[4][40][0].apply(exports,arguments)
},{"dup":40}],299:[function(require,module,exports){
arguments[4][41][0].apply(exports,arguments)
},{"dup":41}],300:[function(require,module,exports){
arguments[4][17][0].apply(exports,arguments)
},{"dup":17}],301:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"dup":18}],302:[function(require,module,exports){
arguments[4][19][0].apply(exports,arguments)
},{"dup":19}],303:[function(require,module,exports){
arguments[4][20][0].apply(exports,arguments)
},{"dup":20}],304:[function(require,module,exports){
arguments[4][21][0].apply(exports,arguments)
},{"dup":21}],305:[function(require,module,exports){
arguments[4][22][0].apply(exports,arguments)
},{"./array":300,"dup":22}],306:[function(require,module,exports){
arguments[4][23][0].apply(exports,arguments)
},{"./lib/array":300,"./lib/dom":301,"./lib/events":302,"./lib/fn":303,"./lib/string":304,"./lib/url":305,"dup":23}],307:[function(require,module,exports){
'use strict';

module.exports = ClassList

var indexOf = require('component-indexof'),
    trim = require('trim'),
    arr = Array.prototype

/**
 * ClassList(elem) is kind of like Element#classList.
 *
 * @param {Element} elem
 * @return {ClassList}
 */
function ClassList (elem) {
  if (!(this instanceof ClassList))
    return new ClassList(elem)

  var classes = trim(elem.className).split(/\s+/),
      i

  this._elem = elem

  this.length = 0

  for (i = 0; i < classes.length; i += 1) {
    if (classes[i])
      arr.push.call(this, classes[i])
  }
}

/**
 * add(class1 [, class2 [, ...]]) adds the given class(es) to the
 * element.
 *
 * @param {String} ...
 * @return {Context}
 */
ClassList.prototype.add = function () {
  var name,
      i

  for (i = 0; i < arguments.length; i += 1) {
    name = '' + arguments[i]

    if (indexOf(this, name) >= 0)
      continue

    arr.push.call(this, name)
  }

  this._elem.className = this.toString()

  return this
}

/**
 * remove(class1 [, class2 [, ...]]) removes the given class(es) from
 * the element.
 *
 * @param {String} ...
 * @return {Context}
 */
ClassList.prototype.remove = function () {
  var index,
      name,
      i

  for (i = 0; i < arguments.length; i += 1) {
    name = '' + arguments[i]
    index = indexOf(this, name)

    if (index < 0) continue

    arr.splice.call(this, index, 1)
  }

  this._elem.className = this.toString()

  return this
}

/**
 * contains(name) determines if the element has a given class.
 *
 * @param {String} name
 * @return {Boolean}
 */
ClassList.prototype.contains = function (name) {
  name += ''
  return indexOf(this, name) >= 0
}

/**
 * toggle(name [, force]) toggles a class. If force is a boolean,
 * this method is basically just an alias for add/remove.
 *
 * @param {String} name
 * @param {Boolean} force
 * @return {Context}
 */
ClassList.prototype.toggle = function (name, force) {
  name += ''

  if (force === true) return this.add(name)
  if (force === false) return this.remove(name)

  return this[this.contains(name) ? 'remove' : 'add'](name)
}

/**
 * toString() returns the className of the element.
 *
 * @return {String}
 */
ClassList.prototype.toString = function () {
  return arr.join.call(this, ' ')
}

},{"component-indexof":308,"trim":309}],308:[function(require,module,exports){
module.exports = function(arr, obj){
  if (arr.indexOf) return arr.indexOf(obj);
  for (var i = 0; i < arr.length; ++i) {
    if (arr[i] === obj) return i;
  }
  return -1;
};
},{}],309:[function(require,module,exports){

exports = module.exports = trim;

function trim(str){
  return str.replace(/^\s*|\s*$/g, '');
}

exports.left = function(str){
  return str.replace(/^\s*/, '');
};

exports.right = function(str){
  return str.replace(/\s*$/, '');
};

},{}],310:[function(require,module,exports){
'use strict';

var assign = require('lodash.assign');
var isString = require('lodash.isstring');
var defaultAttributes = require('./lib/default-attributes');

module.exports = function createFrame(options) {
  var iframe = document.createElement('iframe');
  var config = assign({}, defaultAttributes, options);

  if (config.style && !isString(config.style)) {
    assign(iframe.style, config.style);
    delete config.style;
  }

  for (var key in config) {
    if (config.hasOwnProperty(key)) {
      iframe.setAttribute(key, config[key]);
    }
  }

  if (!iframe.getAttribute('id')) {
    iframe.id = iframe.name;
  }

  return iframe;
};

},{"./lib/default-attributes":311,"lodash.assign":313,"lodash.isstring":312}],311:[function(require,module,exports){
module.exports={
  "frameBorder": 0,
  "allowtransparency": true
}

},{}],312:[function(require,module,exports){
/**
 * lodash 3.0.1 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.2 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/** `Object#toString` result references. */
var stringTag = '[object String]';

/**
 * Checks if `value` is object-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

/** Used for native method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the [`toStringTag`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-object.prototype.tostring)
 * of values.
 */
var objToString = objectProto.toString;

/**
 * Checks if `value` is classified as a `String` primitive or object.
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified, else `false`.
 * @example
 *
 * _.isString('abc');
 * // => true
 *
 * _.isString(1);
 * // => false
 */
function isString(value) {
  return typeof value == 'string' || (isObjectLike(value) && objToString.call(value) == stringTag);
}

module.exports = isString;

},{}],313:[function(require,module,exports){
/**
 * lodash 3.2.0 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */
var baseAssign = require('lodash._baseassign'),
    createAssigner = require('lodash._createassigner'),
    keys = require('lodash.keys');

/**
 * A specialized version of `_.assign` for customizing assigned values without
 * support for argument juggling, multiple sources, and `this` binding `customizer`
 * functions.
 *
 * @private
 * @param {Object} object The destination object.
 * @param {Object} source The source object.
 * @param {Function} customizer The function to customize assigned values.
 * @returns {Object} Returns `object`.
 */
function assignWith(object, source, customizer) {
  var index = -1,
      props = keys(source),
      length = props.length;

  while (++index < length) {
    var key = props[index],
        value = object[key],
        result = customizer(value, source[key], key, object, source);

    if ((result === result ? (result !== value) : (value === value)) ||
        (value === undefined && !(key in object))) {
      object[key] = result;
    }
  }
  return object;
}

/**
 * Assigns own enumerable properties of source object(s) to the destination
 * object. Subsequent sources overwrite property assignments of previous sources.
 * If `customizer` is provided it is invoked to produce the assigned values.
 * The `customizer` is bound to `thisArg` and invoked with five arguments:
 * (objectValue, sourceValue, key, object, source).
 *
 * **Note:** This method mutates `object` and is based on
 * [`Object.assign`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-object.assign).
 *
 * @static
 * @memberOf _
 * @alias extend
 * @category Object
 * @param {Object} object The destination object.
 * @param {...Object} [sources] The source objects.
 * @param {Function} [customizer] The function to customize assigned values.
 * @param {*} [thisArg] The `this` binding of `customizer`.
 * @returns {Object} Returns `object`.
 * @example
 *
 * _.assign({ 'user': 'barney' }, { 'age': 40 }, { 'user': 'fred' });
 * // => { 'user': 'fred', 'age': 40 }
 *
 * // using a customizer callback
 * var defaults = _.partialRight(_.assign, function(value, other) {
 *   return _.isUndefined(value) ? other : value;
 * });
 *
 * defaults({ 'user': 'barney' }, { 'age': 36 }, { 'user': 'fred' });
 * // => { 'user': 'barney', 'age': 36 }
 */
var assign = createAssigner(function(object, source, customizer) {
  return customizer
    ? assignWith(object, source, customizer)
    : baseAssign(object, source);
});

module.exports = assign;

},{"lodash._baseassign":314,"lodash._createassigner":316,"lodash.keys":320}],314:[function(require,module,exports){
/**
 * lodash 3.2.0 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */
var baseCopy = require('lodash._basecopy'),
    keys = require('lodash.keys');

/**
 * The base implementation of `_.assign` without support for argument juggling,
 * multiple sources, and `customizer` functions.
 *
 * @private
 * @param {Object} object The destination object.
 * @param {Object} source The source object.
 * @returns {Object} Returns `object`.
 */
function baseAssign(object, source) {
  return source == null
    ? object
    : baseCopy(source, keys(source), object);
}

module.exports = baseAssign;

},{"lodash._basecopy":315,"lodash.keys":320}],315:[function(require,module,exports){
/**
 * lodash 3.0.1 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/**
 * Copies properties of `source` to `object`.
 *
 * @private
 * @param {Object} source The object to copy properties from.
 * @param {Array} props The property names to copy.
 * @param {Object} [object={}] The object to copy properties to.
 * @returns {Object} Returns `object`.
 */
function baseCopy(source, props, object) {
  object || (object = {});

  var index = -1,
      length = props.length;

  while (++index < length) {
    var key = props[index];
    object[key] = source[key];
  }
  return object;
}

module.exports = baseCopy;

},{}],316:[function(require,module,exports){
/**
 * lodash 3.1.1 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */
var bindCallback = require('lodash._bindcallback'),
    isIterateeCall = require('lodash._isiterateecall'),
    restParam = require('lodash.restparam');

/**
 * Creates a function that assigns properties of source object(s) to a given
 * destination object.
 *
 * **Note:** This function is used to create `_.assign`, `_.defaults`, and `_.merge`.
 *
 * @private
 * @param {Function} assigner The function to assign values.
 * @returns {Function} Returns the new assigner function.
 */
function createAssigner(assigner) {
  return restParam(function(object, sources) {
    var index = -1,
        length = object == null ? 0 : sources.length,
        customizer = length > 2 ? sources[length - 2] : undefined,
        guard = length > 2 ? sources[2] : undefined,
        thisArg = length > 1 ? sources[length - 1] : undefined;

    if (typeof customizer == 'function') {
      customizer = bindCallback(customizer, thisArg, 5);
      length -= 2;
    } else {
      customizer = typeof thisArg == 'function' ? thisArg : undefined;
      length -= (customizer ? 1 : 0);
    }
    if (guard && isIterateeCall(sources[0], sources[1], guard)) {
      customizer = length < 3 ? undefined : customizer;
      length = 1;
    }
    while (++index < length) {
      var source = sources[index];
      if (source) {
        assigner(object, source, customizer);
      }
    }
    return object;
  });
}

module.exports = createAssigner;

},{"lodash._bindcallback":317,"lodash._isiterateecall":318,"lodash.restparam":319}],317:[function(require,module,exports){
/**
 * lodash 3.0.1 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/**
 * A specialized version of `baseCallback` which only supports `this` binding
 * and specifying the number of arguments to provide to `func`.
 *
 * @private
 * @param {Function} func The function to bind.
 * @param {*} thisArg The `this` binding of `func`.
 * @param {number} [argCount] The number of arguments to provide to `func`.
 * @returns {Function} Returns the callback.
 */
function bindCallback(func, thisArg, argCount) {
  if (typeof func != 'function') {
    return identity;
  }
  if (thisArg === undefined) {
    return func;
  }
  switch (argCount) {
    case 1: return function(value) {
      return func.call(thisArg, value);
    };
    case 3: return function(value, index, collection) {
      return func.call(thisArg, value, index, collection);
    };
    case 4: return function(accumulator, value, index, collection) {
      return func.call(thisArg, accumulator, value, index, collection);
    };
    case 5: return function(value, other, key, object, source) {
      return func.call(thisArg, value, other, key, object, source);
    };
  }
  return function() {
    return func.apply(thisArg, arguments);
  };
}

/**
 * This method returns the first argument provided to it.
 *
 * @static
 * @memberOf _
 * @category Utility
 * @param {*} value Any value.
 * @returns {*} Returns `value`.
 * @example
 *
 * var object = { 'user': 'fred' };
 *
 * _.identity(object) === object;
 * // => true
 */
function identity(value) {
  return value;
}

module.exports = bindCallback;

},{}],318:[function(require,module,exports){
/**
 * lodash 3.0.9 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/** Used to detect unsigned integer values. */
var reIsUint = /^\d+$/;

/**
 * Used as the [maximum length](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-number.max_safe_integer)
 * of an array-like value.
 */
var MAX_SAFE_INTEGER = 9007199254740991;

/**
 * The base implementation of `_.property` without support for deep paths.
 *
 * @private
 * @param {string} key The key of the property to get.
 * @returns {Function} Returns the new function.
 */
function baseProperty(key) {
  return function(object) {
    return object == null ? undefined : object[key];
  };
}

/**
 * Gets the "length" property value of `object`.
 *
 * **Note:** This function is used to avoid a [JIT bug](https://bugs.webkit.org/show_bug.cgi?id=142792)
 * that affects Safari on at least iOS 8.1-8.3 ARM64.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {*} Returns the "length" value.
 */
var getLength = baseProperty('length');

/**
 * Checks if `value` is array-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
 */
function isArrayLike(value) {
  return value != null && isLength(getLength(value));
}

/**
 * Checks if `value` is a valid array-like index.
 *
 * @private
 * @param {*} value The value to check.
 * @param {number} [length=MAX_SAFE_INTEGER] The upper bounds of a valid index.
 * @returns {boolean} Returns `true` if `value` is a valid index, else `false`.
 */
function isIndex(value, length) {
  value = (typeof value == 'number' || reIsUint.test(value)) ? +value : -1;
  length = length == null ? MAX_SAFE_INTEGER : length;
  return value > -1 && value % 1 == 0 && value < length;
}

/**
 * Checks if the provided arguments are from an iteratee call.
 *
 * @private
 * @param {*} value The potential iteratee value argument.
 * @param {*} index The potential iteratee index or key argument.
 * @param {*} object The potential iteratee object argument.
 * @returns {boolean} Returns `true` if the arguments are from an iteratee call, else `false`.
 */
function isIterateeCall(value, index, object) {
  if (!isObject(object)) {
    return false;
  }
  var type = typeof index;
  if (type == 'number'
      ? (isArrayLike(object) && isIndex(index, object.length))
      : (type == 'string' && index in object)) {
    var other = object[index];
    return value === value ? (value === other) : (other !== other);
  }
  return false;
}

/**
 * Checks if `value` is a valid array-like length.
 *
 * **Note:** This function is based on [`ToLength`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-tolength).
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
 */
function isLength(value) {
  return typeof value == 'number' && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
}

/**
 * Checks if `value` is the [language type](https://es5.github.io/#x8) of `Object`.
 * (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is an object, else `false`.
 * @example
 *
 * _.isObject({});
 * // => true
 *
 * _.isObject([1, 2, 3]);
 * // => true
 *
 * _.isObject(1);
 * // => false
 */
function isObject(value) {
  // Avoid a V8 JIT bug in Chrome 19-20.
  // See https://code.google.com/p/v8/issues/detail?id=2291 for more details.
  var type = typeof value;
  return !!value && (type == 'object' || type == 'function');
}

module.exports = isIterateeCall;

},{}],319:[function(require,module,exports){
/**
 * lodash 3.6.1 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/** Used as the `TypeError` message for "Functions" methods. */
var FUNC_ERROR_TEXT = 'Expected a function';

/* Native method references for those with the same name as other `lodash` methods. */
var nativeMax = Math.max;

/**
 * Creates a function that invokes `func` with the `this` binding of the
 * created function and arguments from `start` and beyond provided as an array.
 *
 * **Note:** This method is based on the [rest parameter](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Functions/rest_parameters).
 *
 * @static
 * @memberOf _
 * @category Function
 * @param {Function} func The function to apply a rest parameter to.
 * @param {number} [start=func.length-1] The start position of the rest parameter.
 * @returns {Function} Returns the new function.
 * @example
 *
 * var say = _.restParam(function(what, names) {
 *   return what + ' ' + _.initial(names).join(', ') +
 *     (_.size(names) > 1 ? ', & ' : '') + _.last(names);
 * });
 *
 * say('hello', 'fred', 'barney', 'pebbles');
 * // => 'hello fred, barney, & pebbles'
 */
function restParam(func, start) {
  if (typeof func != 'function') {
    throw new TypeError(FUNC_ERROR_TEXT);
  }
  start = nativeMax(start === undefined ? (func.length - 1) : (+start || 0), 0);
  return function() {
    var args = arguments,
        index = -1,
        length = nativeMax(args.length - start, 0),
        rest = Array(length);

    while (++index < length) {
      rest[index] = args[start + index];
    }
    switch (start) {
      case 0: return func.call(this, rest);
      case 1: return func.call(this, args[0], rest);
      case 2: return func.call(this, args[0], args[1], rest);
    }
    var otherArgs = Array(start + 1);
    index = -1;
    while (++index < start) {
      otherArgs[index] = args[index];
    }
    otherArgs[start] = rest;
    return func.apply(this, otherArgs);
  };
}

module.exports = restParam;

},{}],320:[function(require,module,exports){
/**
 * lodash 3.1.1 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */
var getNative = require('lodash._getnative'),
    isArguments = require('lodash.isarguments'),
    isArray = require('lodash.isarray');

/** Used to detect unsigned integer values. */
var reIsUint = /^\d+$/;

/** Used for native method references. */
var objectProto = Object.prototype;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/* Native method references for those with the same name as other `lodash` methods. */
var nativeKeys = getNative(Object, 'keys');

/**
 * Used as the [maximum length](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-number.max_safe_integer)
 * of an array-like value.
 */
var MAX_SAFE_INTEGER = 9007199254740991;

/**
 * The base implementation of `_.property` without support for deep paths.
 *
 * @private
 * @param {string} key The key of the property to get.
 * @returns {Function} Returns the new function.
 */
function baseProperty(key) {
  return function(object) {
    return object == null ? undefined : object[key];
  };
}

/**
 * Gets the "length" property value of `object`.
 *
 * **Note:** This function is used to avoid a [JIT bug](https://bugs.webkit.org/show_bug.cgi?id=142792)
 * that affects Safari on at least iOS 8.1-8.3 ARM64.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {*} Returns the "length" value.
 */
var getLength = baseProperty('length');

/**
 * Checks if `value` is array-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
 */
function isArrayLike(value) {
  return value != null && isLength(getLength(value));
}

/**
 * Checks if `value` is a valid array-like index.
 *
 * @private
 * @param {*} value The value to check.
 * @param {number} [length=MAX_SAFE_INTEGER] The upper bounds of a valid index.
 * @returns {boolean} Returns `true` if `value` is a valid index, else `false`.
 */
function isIndex(value, length) {
  value = (typeof value == 'number' || reIsUint.test(value)) ? +value : -1;
  length = length == null ? MAX_SAFE_INTEGER : length;
  return value > -1 && value % 1 == 0 && value < length;
}

/**
 * Checks if `value` is a valid array-like length.
 *
 * **Note:** This function is based on [`ToLength`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-tolength).
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
 */
function isLength(value) {
  return typeof value == 'number' && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
}

/**
 * A fallback implementation of `Object.keys` which creates an array of the
 * own enumerable property names of `object`.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {Array} Returns the array of property names.
 */
function shimKeys(object) {
  var props = keysIn(object),
      propsLength = props.length,
      length = propsLength && object.length;

  var allowIndexes = !!length && isLength(length) &&
    (isArray(object) || isArguments(object));

  var index = -1,
      result = [];

  while (++index < propsLength) {
    var key = props[index];
    if ((allowIndexes && isIndex(key, length)) || hasOwnProperty.call(object, key)) {
      result.push(key);
    }
  }
  return result;
}

/**
 * Checks if `value` is the [language type](https://es5.github.io/#x8) of `Object`.
 * (e.g. arrays, functions, objects, regexes, `new Number(0)`, and `new String('')`)
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is an object, else `false`.
 * @example
 *
 * _.isObject({});
 * // => true
 *
 * _.isObject([1, 2, 3]);
 * // => true
 *
 * _.isObject(1);
 * // => false
 */
function isObject(value) {
  // Avoid a V8 JIT bug in Chrome 19-20.
  // See https://code.google.com/p/v8/issues/detail?id=2291 for more details.
  var type = typeof value;
  return !!value && (type == 'object' || type == 'function');
}

/**
 * Creates an array of the own enumerable property names of `object`.
 *
 * **Note:** Non-object values are coerced to objects. See the
 * [ES spec](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-object.keys)
 * for more details.
 *
 * @static
 * @memberOf _
 * @category Object
 * @param {Object} object The object to query.
 * @returns {Array} Returns the array of property names.
 * @example
 *
 * function Foo() {
 *   this.a = 1;
 *   this.b = 2;
 * }
 *
 * Foo.prototype.c = 3;
 *
 * _.keys(new Foo);
 * // => ['a', 'b'] (iteration order is not guaranteed)
 *
 * _.keys('hi');
 * // => ['0', '1']
 */
var keys = !nativeKeys ? shimKeys : function(object) {
  var Ctor = object == null ? null : object.constructor;
  if ((typeof Ctor == 'function' && Ctor.prototype === object) ||
      (typeof object != 'function' && isArrayLike(object))) {
    return shimKeys(object);
  }
  return isObject(object) ? nativeKeys(object) : [];
};

/**
 * Creates an array of the own and inherited enumerable property names of `object`.
 *
 * **Note:** Non-object values are coerced to objects.
 *
 * @static
 * @memberOf _
 * @category Object
 * @param {Object} object The object to query.
 * @returns {Array} Returns the array of property names.
 * @example
 *
 * function Foo() {
 *   this.a = 1;
 *   this.b = 2;
 * }
 *
 * Foo.prototype.c = 3;
 *
 * _.keysIn(new Foo);
 * // => ['a', 'b', 'c'] (iteration order is not guaranteed)
 */
function keysIn(object) {
  if (object == null) {
    return [];
  }
  if (!isObject(object)) {
    object = Object(object);
  }
  var length = object.length;
  length = (length && isLength(length) &&
    (isArray(object) || isArguments(object)) && length) || 0;

  var Ctor = object.constructor,
      index = -1,
      isProto = typeof Ctor == 'function' && Ctor.prototype === object,
      result = Array(length),
      skipIndexes = length > 0;

  while (++index < length) {
    result[index] = (index + '');
  }
  for (var key in object) {
    if (!(skipIndexes && isIndex(key, length)) &&
        !(key == 'constructor' && (isProto || !hasOwnProperty.call(object, key)))) {
      result.push(key);
    }
  }
  return result;
}

module.exports = keys;

},{"lodash._getnative":321,"lodash.isarguments":322,"lodash.isarray":323}],321:[function(require,module,exports){
/**
 * lodash 3.9.0 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/** `Object#toString` result references. */
var funcTag = '[object Function]';

/**
 * Used to match `RegExp` [special characters](http://www.regular-expressions.info/characters.html#special).
 * In addition to special characters the forward slash is escaped to allow for
 * easier `eval` use and `Function` compilation.
 */
var reRegExpChars = /[.*+?^${}()|[\]\/\\]/g,
    reHasRegExpChars = RegExp(reRegExpChars.source);

/** Used to detect host constructors (Safari > 5). */
var reIsHostCtor = /^\[object .+?Constructor\]$/;

/**
 * Converts `value` to a string if it's not one. An empty string is returned
 * for `null` or `undefined` values.
 *
 * @private
 * @param {*} value The value to process.
 * @returns {string} Returns the string.
 */
function baseToString(value) {
  if (typeof value == 'string') {
    return value;
  }
  return value == null ? '' : (value + '');
}

/**
 * Checks if `value` is object-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

/** Used for native method references. */
var objectProto = Object.prototype;

/** Used to resolve the decompiled source of functions. */
var fnToString = Function.prototype.toString;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * Used to resolve the [`toStringTag`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-object.prototype.tostring)
 * of values.
 */
var objToString = objectProto.toString;

/** Used to detect if a method is native. */
var reIsNative = RegExp('^' +
  escapeRegExp(fnToString.call(hasOwnProperty))
  .replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, '$1.*?') + '$'
);

/**
 * Gets the native function at `key` of `object`.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {string} key The key of the method to get.
 * @returns {*} Returns the function if it's native, else `undefined`.
 */
function getNative(object, key) {
  var value = object == null ? undefined : object[key];
  return isNative(value) ? value : undefined;
}

/**
 * Checks if `value` is a native function.
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a native function, else `false`.
 * @example
 *
 * _.isNative(Array.prototype.push);
 * // => true
 *
 * _.isNative(_);
 * // => false
 */
function isNative(value) {
  if (value == null) {
    return false;
  }
  if (objToString.call(value) == funcTag) {
    return reIsNative.test(fnToString.call(value));
  }
  return isObjectLike(value) && reIsHostCtor.test(value);
}

/**
 * Escapes the `RegExp` special characters "\", "/", "^", "$", ".", "|", "?",
 * "*", "+", "(", ")", "[", "]", "{" and "}" in `string`.
 *
 * @static
 * @memberOf _
 * @category String
 * @param {string} [string=''] The string to escape.
 * @returns {string} Returns the escaped string.
 * @example
 *
 * _.escapeRegExp('[lodash](https://lodash.com/)');
 * // => '\[lodash\]\(https:\/\/lodash\.com\/\)'
 */
function escapeRegExp(string) {
  string = baseToString(string);
  return (string && reHasRegExpChars.test(string))
    ? string.replace(reRegExpChars, '\\$&')
    : string;
}

module.exports = getNative;

},{}],322:[function(require,module,exports){
/**
 * lodash 3.0.3 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/** `Object#toString` result references. */
var argsTag = '[object Arguments]';

/**
 * Checks if `value` is object-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

/** Used for native method references. */
var objectProto = Object.prototype;

/**
 * Used to resolve the [`toStringTag`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-object.prototype.tostring)
 * of values.
 */
var objToString = objectProto.toString;

/**
 * Used as the [maximum length](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-number.max_safe_integer)
 * of an array-like value.
 */
var MAX_SAFE_INTEGER = 9007199254740991;

/**
 * The base implementation of `_.property` without support for deep paths.
 *
 * @private
 * @param {string} key The key of the property to get.
 * @returns {Function} Returns the new function.
 */
function baseProperty(key) {
  return function(object) {
    return object == null ? undefined : object[key];
  };
}

/**
 * Gets the "length" property value of `object`.
 *
 * **Note:** This function is used to avoid a [JIT bug](https://bugs.webkit.org/show_bug.cgi?id=142792)
 * that affects Safari on at least iOS 8.1-8.3 ARM64.
 *
 * @private
 * @param {Object} object The object to query.
 * @returns {*} Returns the "length" value.
 */
var getLength = baseProperty('length');

/**
 * Checks if `value` is array-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is array-like, else `false`.
 */
function isArrayLike(value) {
  return value != null && isLength(getLength(value));
}

/**
 * Checks if `value` is a valid array-like length.
 *
 * **Note:** This function is based on [`ToLength`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-tolength).
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
 */
function isLength(value) {
  return typeof value == 'number' && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
}

/**
 * Checks if `value` is classified as an `arguments` object.
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified, else `false`.
 * @example
 *
 * _.isArguments(function() { return arguments; }());
 * // => true
 *
 * _.isArguments([1, 2, 3]);
 * // => false
 */
function isArguments(value) {
  return isObjectLike(value) && isArrayLike(value) && objToString.call(value) == argsTag;
}

module.exports = isArguments;

},{}],323:[function(require,module,exports){
/**
 * lodash 3.0.3 (Custom Build) <https://lodash.com/>
 * Build: `lodash modern modularize exports="npm" -o ./`
 * Copyright 2012-2015 The Dojo Foundation <http://dojofoundation.org/>
 * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
 * Copyright 2009-2015 Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
 * Available under MIT license <https://lodash.com/license>
 */

/** `Object#toString` result references. */
var arrayTag = '[object Array]',
    funcTag = '[object Function]';

/**
 * Used to match `RegExp` [special characters](http://www.regular-expressions.info/characters.html#special).
 * In addition to special characters the forward slash is escaped to allow for
 * easier `eval` use and `Function` compilation.
 */
var reRegExpChars = /[.*+?^${}()|[\]\/\\]/g,
    reHasRegExpChars = RegExp(reRegExpChars.source);

/** Used to detect host constructors (Safari > 5). */
var reIsHostCtor = /^\[object .+?Constructor\]$/;

/**
 * Converts `value` to a string if it's not one. An empty string is returned
 * for `null` or `undefined` values.
 *
 * @private
 * @param {*} value The value to process.
 * @returns {string} Returns the string.
 */
function baseToString(value) {
  if (typeof value == 'string') {
    return value;
  }
  return value == null ? '' : (value + '');
}

/**
 * Checks if `value` is object-like.
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is object-like, else `false`.
 */
function isObjectLike(value) {
  return !!value && typeof value == 'object';
}

/** Used for native method references. */
var objectProto = Object.prototype;

/** Used to resolve the decompiled source of functions. */
var fnToString = Function.prototype.toString;

/** Used to check objects for own properties. */
var hasOwnProperty = objectProto.hasOwnProperty;

/**
 * Used to resolve the [`toStringTag`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-object.prototype.tostring)
 * of values.
 */
var objToString = objectProto.toString;

/** Used to detect if a method is native. */
var reIsNative = RegExp('^' +
  escapeRegExp(fnToString.call(hasOwnProperty))
  .replace(/hasOwnProperty|(function).*?(?=\\\()| for .+?(?=\\\])/g, '$1.*?') + '$'
);

/* Native method references for those with the same name as other `lodash` methods. */
var nativeIsArray = getNative(Array, 'isArray');

/**
 * Used as the [maximum length](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-number.max_safe_integer)
 * of an array-like value.
 */
var MAX_SAFE_INTEGER = 9007199254740991;

/**
 * Gets the native function at `key` of `object`.
 *
 * @private
 * @param {Object} object The object to query.
 * @param {string} key The key of the method to get.
 * @returns {*} Returns the function if it's native, else `undefined`.
 */
function getNative(object, key) {
  var value = object == null ? undefined : object[key];
  return isNative(value) ? value : undefined;
}

/**
 * Checks if `value` is a valid array-like length.
 *
 * **Note:** This function is based on [`ToLength`](https://people.mozilla.org/~jorendorff/es6-draft.html#sec-tolength).
 *
 * @private
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a valid length, else `false`.
 */
function isLength(value) {
  return typeof value == 'number' && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
}

/**
 * Checks if `value` is classified as an `Array` object.
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is correctly classified, else `false`.
 * @example
 *
 * _.isArray([1, 2, 3]);
 * // => true
 *
 * _.isArray(function() { return arguments; }());
 * // => false
 */
var isArray = nativeIsArray || function(value) {
  return isObjectLike(value) && isLength(value.length) && objToString.call(value) == arrayTag;
};

/**
 * Checks if `value` is a native function.
 *
 * @static
 * @memberOf _
 * @category Lang
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a native function, else `false`.
 * @example
 *
 * _.isNative(Array.prototype.push);
 * // => true
 *
 * _.isNative(_);
 * // => false
 */
function isNative(value) {
  if (value == null) {
    return false;
  }
  if (objToString.call(value) == funcTag) {
    return reIsNative.test(fnToString.call(value));
  }
  return isObjectLike(value) && reIsHostCtor.test(value);
}

/**
 * Escapes the `RegExp` special characters "\", "/", "^", "$", ".", "|", "?",
 * "*", "+", "(", ")", "[", "]", "{" and "}" in `string`.
 *
 * @static
 * @memberOf _
 * @category String
 * @param {string} [string=''] The string to escape.
 * @returns {string} Returns the escaped string.
 * @example
 *
 * _.escapeRegExp('[lodash](https://lodash.com/)');
 * // => '\[lodash\]\(https:\/\/lodash\.com\/\)'
 */
function escapeRegExp(string) {
  string = baseToString(string);
  return (string && reHasRegExpChars.test(string))
    ? string.replace(reRegExpChars, '\\$&')
    : string;
}

module.exports = isArray;

},{}],324:[function(require,module,exports){
function nodeListToArray(nodeList) {
  try {
    return Array.prototype.slice.call(nodeList);
  } catch (err) {
    var result = [];
    for (var i = 0; i < nodeList.length; i++) {
      result.push(nodeList[i]);
    }
    return result;
  }
}

if (typeof module !== 'undefined') {
  module.exports = nodeListToArray;
}

},{}],325:[function(require,module,exports){
module.exports = function shallowClone(obj) {
  var result = {};

  for (var key in obj) {
    if (obj.hasOwnProperty(key)) {
      result[key] = obj[key];
    }
  }

  return result;
};

},{}],326:[function(require,module,exports){
'use strict';
/*eslint-disable consistent-return*/

function convertToLegacyShippingAddress (address) {
  var prop;
  var legacyShippingAddress = {};

  if (!address) {
    return;
  }

  for (prop in address) {
    if (address.hasOwnProperty(prop)) {
      legacyShippingAddress[toSnakeCase(prop)] = address[prop];
    }
  }

  return legacyShippingAddress;
}

function toSnakeCase (string) {
  return string.replace(/([A-Z])/g, function ($1) {
    return '_' + $1.toLowerCase();
  });
}

module.exports = { convertToLegacyShippingAddress: convertToLegacyShippingAddress };

},{}],327:[function(require,module,exports){
'use strict';

module.exports = {
  ROOT_SUCCESS_CALLBACK: 'onPaymentMethodReceived',
  ROOT_ERROR_CALLBACK: 'onError',
  ROOT_READY_CALLBACK: 'onReady'
};

},{}],328:[function(require,module,exports){
'use strict';

var api = require('braintree-api');
var coinbase = require('braintree-coinbase');
var bus = require('braintree-bus');

function initialize(clientToken, options) {
  bus.on(bus.events.PAYMENT_METHOD_GENERATED, function (payload) {
    bus.emit(bus.events.PAYMENT_METHOD_RECEIVED, payload);
  });

  options.coinbase = options.coinbase || {};
  options.apiClient = new api.Client({
    clientToken: clientToken,
    integration: 'coinbase'
  });

  return coinbase.create(options);
}

module.exports = {initialize: initialize};

},{"braintree-api":16,"braintree-bus":39,"braintree-coinbase":42}],329:[function(require,module,exports){
'use strict';

var api = require('braintree-api');

var setupHostedFields = require('./setup-hosted-fields');
var setupPayPal = require('./setup-paypal');
var setupForm = require('./setup-form');
var setupCoinbase = require('./setup-coinbase');

function initialize(clientToken, options) {
  var apiClient = new api.Client({
    clientToken: clientToken,
    integration: 'custom'
  });

  if (options.hostedFields != null) {
    setupHostedFields(options, apiClient);
  } else {
    setupForm(options, apiClient);
  }
  setupPayPal(options, clientToken);
  setupCoinbase(options, apiClient);
}

module.exports = {initialize: initialize};

},{"./setup-coinbase":330,"./setup-form":331,"./setup-hosted-fields":332,"./setup-paypal":333,"braintree-api":16}],330:[function(require,module,exports){
'use strict';

var coinbase = require('braintree-coinbase');

function setupCoinbase(options, apiClient) {
  if (!options.coinbase) { return; }

  options.apiClient = apiClient;

  if (options.paypal) {
    delete options.paypal;
  }

  coinbase.create(options);
}

module.exports = setupCoinbase;

},{"braintree-coinbase":42}],331:[function(require,module,exports){
'use strict';

var form = require('braintree-form');
var utils = require('braintree-utilities');
var constants = require('../../constants');
var bus = require('braintree-bus');

function setupForm(options, apiClient) {
  var formIntegration;

  if (options.id) {
    formIntegration = form.setup(apiClient, options);

    if (utils.isFunction(options[constants.ROOT_SUCCESS_CALLBACK])) {
      formIntegration.onNonceReceived = function (err, payload) {
        if (err) {
          bus.emit(bus.events.ERROR, err);
        } else {
          options[constants.ROOT_SUCCESS_CALLBACK](payload);
        }
      };
    }
  } else {
    bus.on(bus.events.PAYMENT_METHOD_GENERATED, function (payload) {
      bus.emit(bus.events.PAYMENT_METHOD_RECEIVED, payload);
    });
  }
}

module.exports = setupForm;

},{"../../constants":327,"braintree-bus":39,"braintree-form":202,"braintree-utilities":289}],332:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');
var INPUT_NAME = 'payment_method_nonce';
var FormNapper = require('form-napper');
var hostedFields = require('hosted-fields');
var bus = require('braintree-bus');
var constants = require('../../constants');

function handleNonceGeneration(formNapper, rootCallback, apiClient) {
  var paymentMethod;
  var analyticsString = 'web.custom.hosted-fields.via.';

  bus.on(bus.events.PAYMENT_METHOD_CANCELLED, function () {
    paymentMethod = null;
    formNapper.inject(INPUT_NAME, '');
  });
  bus.on(bus.events.PAYMENT_METHOD_GENERATED, function (payload) {
    paymentMethod = payload;
    formNapper.inject(INPUT_NAME, paymentMethod.nonce);
  });

  return function () {
    bus.emit(hostedFields.events.TOKENIZATION_REQUEST, function (args) {
      var err = args[0];
      var payload = args[1];

      if (err) {
        bus.emit(bus.events.ERROR, err);
        return;
      }

      paymentMethod = payload || paymentMethod;

      if (paymentMethod == null) {
        bus.emit(hostedFields.events.VALIDATE_STRICT);
        bus.emit(bus.events.ERROR, {
          type: 'VALIDATION',
          message: 'User did not enter a payment method'
        });
        return;
      }

      if (rootCallback) {
        apiClient.sendAnalyticsEvents(analyticsString + 'callback.success', function () {
          rootCallback(paymentMethod);
        });
      } else {
        apiClient.sendAnalyticsEvents(analyticsString + 'fields.via.formsubmit.success', function () {
          formNapper.inject(INPUT_NAME, paymentMethod.nonce);
          formNapper.submit();
        });
      }
    });
  };
}

function setupHostedFields(options, apiClient) {
  var formNapper, submitRequestHandler, rootCallback;

  if (options.id) {
    formNapper = new FormNapper(options.id);
    hostedFields.setup(options);

    if (formNapper.htmlForm == null) {
      bus.emit(bus.events.ERROR, {
        type: 'CONFIGURATION',
        message: 'options.id does not reference a valid DOM element'
      });
      return;
    }

    if (utils.isFunction(options[constants.ROOT_SUCCESS_CALLBACK])) {
      rootCallback = options[constants.ROOT_SUCCESS_CALLBACK];
    }

    submitRequestHandler = handleNonceGeneration(formNapper, rootCallback, apiClient);

    formNapper.hijack(submitRequestHandler);
    bus.on(bus.events.USER_FORM_SUBMIT_REQUEST, submitRequestHandler);
  } else {
    bus.on(bus.events.PAYMENT_METHOD_GENERATED, function (payload) {
      bus.emit(bus.events.PAYMENT_METHOD_RECEIVED, payload);
    });
  }
}

module.exports = setupHostedFields;

},{"../../constants":327,"braintree-bus":39,"braintree-utilities":289,"form-napper":290,"hosted-fields":291}],333:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');
var paypal = require('braintree-paypal');
var bus = require('braintree-bus');
var convertToLegacyShippingAddress = require('../../compatibility').convertToLegacyShippingAddress;

function setupPayPal(options, clientToken) {
  var paypalCallbackLookup, legacyPaypalSuccessCallback, legacyPaypalCancelledCallback, dummyInput;

  if (!options.paypal) { return; }

  paypalCallbackLookup = getIntegrationCallbackLookup(options, 'paypal');
  legacyPaypalSuccessCallback = paypalCallbackLookup('onSuccess');
  legacyPaypalCancelledCallback = paypalCallbackLookup('onCancelled');

  if (!options.paypal.paymentMethodNonceInputField) {
    dummyInput = document.createElement('input');
    dummyInput.id = 'braintree-custom-integration-dummy-input';
    options.paypal.paymentMethodNonceInputField = dummyInput;
  }

  options.paypal.onSuccess = function (payload) {
    bus.emit(bus.events.PAYMENT_METHOD_GENERATED, payload);
    legacyPaypalSuccessCallback.apply(null, [
      payload.nonce,
      payload.details.email,
      convertToLegacyShippingAddress(payload.details.shippingAddress)
    ]);
  };

  options.paypal.onCancelled = function () {
    bus.emit(bus.events.PAYMENT_METHOD_CANCELLED);
    legacyPaypalCancelledCallback();
  };

  paypal.create(clientToken, options.paypal);
}

function getIntegrationCallbackLookup(options, integration) {
  return function (funcName) {
    if (integration in options && utils.isFunction(options[integration][funcName])) {
      return options[integration][funcName];
    }
    return function noop() {};
  };
}

module.exports = setupPayPal;

},{"../../compatibility":326,"braintree-bus":39,"braintree-paypal":269,"braintree-utilities":289}],334:[function(require,module,exports){
'use strict';

var dropin = require('braintree-dropin');
var utils = require('braintree-utilities');
var bus = require('braintree-bus');
var constants = require('../constants');
var sanitizePayload = require('../lib/sanitize-payload');

function _getLegacyCallback(options) {
  if (utils.isFunction(options.paymentMethodNonceReceived)) {
    return options.paymentMethodNonceReceived;
  }

  return null;
}

function _hasRootCallback(options) {
  return utils.isFunction(options[constants.ROOT_SUCCESS_CALLBACK]);
}

function initialize(clientToken, options) {
  var legacyCallback = _getLegacyCallback(options);
  var rootCallback = _hasRootCallback(options);

  if (legacyCallback || rootCallback) {
    options.paymentMethodNonceReceived = function (payload) {
      if (legacyCallback) {
        legacyCallback.apply(null, [payload.originalEvent, payload.nonce]);
      }

      delete payload.originalEvent;
      bus.emit(bus.events.PAYMENT_METHOD_RECEIVED, sanitizePayload(payload));
    };
  }

  return dropin.create(clientToken, options);
}

module.exports = {initialize: initialize};

},{"../constants":327,"../lib/sanitize-payload":339,"braintree-bus":39,"braintree-dropin":192,"braintree-utilities":289}],335:[function(require,module,exports){
'use strict';

module.exports = {
  custom: require('./custom'),
  dropin: require('./dropin'),
  paypal: require('./paypal'),
  coinbase: require('./coinbase')
};

},{"./coinbase":328,"./custom":329,"./dropin":334,"./paypal":336}],336:[function(require,module,exports){
'use strict';

var paypal = require('braintree-paypal');
var utils = require('braintree-utilities');
var constants = require('../constants');
var bus = require('braintree-bus');
var convertToLegacyShippingAddress = require('../compatibility').convertToLegacyShippingAddress;

function _getLegacyCallback(options) {
  if ('onSuccess' in options && utils.isFunction(options.onSuccess)) {
    return options.onSuccess;
  } else if ('paypal' in options && utils.isFunction(options.paypal.onSuccess)) {
    return options.paypal.onSuccess;
  }

  return null;
}

function _hasRootCallback(options) {
  return utils.isFunction(options[constants.ROOT_SUCCESS_CALLBACK]);
}

function initialize(clientToken, options) {
  var legacyCallback = _getLegacyCallback(options);
  var rootCallback = _hasRootCallback(options);

  if (legacyCallback || rootCallback) {
    options.onSuccess = function (payload) {
      if (legacyCallback) {
        legacyCallback.apply(null, [
          payload.nonce,
          payload.details.email,
          convertToLegacyShippingAddress(payload.details.shippingAddress)
        ]);
      }

      bus.emit(bus.events.PAYMENT_METHOD_RECEIVED, payload);
    };
  }

  return paypal.create(clientToken, options);
}

module.exports = {initialize: initialize};

},{"../compatibility":326,"../constants":327,"braintree-bus":39,"braintree-paypal":269,"braintree-utilities":289}],337:[function(require,module,exports){
'use strict';

var api = require('braintree-api');
var bus = require('braintree-bus');

function listenForAnalytics(clientToken, integration) {
  var prefix = 'web.' + integration + '.';
  var client = new api.Client({
    clientToken: clientToken,
    integration: integration
  });

  bus.on(bus.events.SEND_ANALYTICS_EVENTS, function (events) {
    var i;

    if (!(events instanceof Array)) {
      events = [events];
    }

    for (i = 0; i < events.length; i++) {
      events[i] = prefix + events[i];
    }

    client.sendAnalyticsEvents(events);
  });
}

module.exports = listenForAnalytics;

},{"braintree-api":16,"braintree-bus":39}],338:[function(require,module,exports){
'use strict';
var bus = require('braintree-bus');
var util = require('braintree-utilities');

function Waiter(callback) {
  this.callback = callback;
  this.counter = 0;

  this.attachEvents();
}

Waiter.prototype.attachEvents = function () {
  this.initHandler = util.bind(this.handleDependencyInitializing, this);
  this.readyHandler = util.bind(this.handleDependencyReady, this);
  bus.on(bus.events.ASYNC_DEPENDENCY_INITIALIZING, this.initHandler);
  bus.on(bus.events.ASYNC_DEPENDENCY_READY, this.readyHandler);
};

Waiter.prototype.handleDependencyInitializing = function () {
  this.counter++;
};

Waiter.prototype.handleDependencyReady = function () {
  this.counter--;

  if (this.counter === 0) {
    this.detachEvents();
    this.callback();
  }
};

Waiter.prototype.detachEvents = function () {
  bus.off(bus.events.ASYNC_DEPENDENCY_INITIALIZING, this.initHandler);
  bus.off(bus.events.ASYNC_DEPENDENCY_READY, this.readyHandler);
};

module.exports = function (cb) {
  return new Waiter(cb);
};

},{"braintree-bus":39,"braintree-utilities":289}],339:[function(require,module,exports){
'use strict';

module.exports = function sanitizePayload(payload) {
  return {
    nonce: payload.nonce,
    details: payload.details,
    type: payload.type
  };
};

},{}]},{},[1])(1)
});