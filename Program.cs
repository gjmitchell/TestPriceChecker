using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography;
using System.Web;
using System.Net;

namespace TestPriceChecker
{
    class Program
    {
        private const string C_AWSAccessKeyId = "AKIAJ7PLMB2AD6V63DSA";
        private const string C_AWSSecretKey = "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";
        private const string C_AssociateTag = "amazpricche08-21";
        private const string c_AWSEndpoint = "webservices.amazon.co.uk";


        static void Main(string[] args)
        {
            string ASIN = "B00M0F0PR6";
            MakeRequest(ASIN);
        }

        private static void MakeRequest(string ASIN)
        {
            //SignedRequestHelper helper = new SignedRequestHelper("AWSAccessKey", "AWSSecret", "AWSEndpoint", "AssociateTag");
            SignedRequestHelper helper = new SignedRequestHelper(C_AWSAccessKeyId, C_AWSSecretKey, c_AWSEndpoint, C_AssociateTag);
            IDictionary<string, string> r1 = new Dictionary<string, String>();
            r1["Service"] = "AWSECommerceService";
            r1["Operation"] = "ItemLookup";
            r1["ItemId"] = ASIN;
            r1["ItemType"] = "ASIN";
            r1["ResponseGroup"] = "Offers";
            r1["Version"] = "2009-01-06";

            string strRequestUrl = helper.Sign(r1);
            string price = GetPrice(strRequestUrl);
        }

        private static string GetPrice(string url)
        {
            string strResult = string.Empty;

            try
            {
                WebRequest request = HttpWebRequest.Create(url);
                WebResponse response = request.GetResponse();
                XmlDocument doc = new XmlDocument();
                doc.Load(response.GetResponseStream());

                XmlNodeList errorMessageNodes = doc.GetElementsByTagName("Message");
                if (errorMessageNodes != null && errorMessageNodes.Count > 0)
                {
                    String message = errorMessageNodes.Item(0).InnerText;
                    return "Error: " + message + " (but signature worked)";
                }

                // custom to whatever ResponseGroup you chose
                XmlNodeList el = doc.GetElementsByTagName("Price");
                XmlNode node = el[0];
                XmlNode node2 = node["FormattedPrice"];
                strResult = node2.InnerText;
                response.Close();
            }

            catch (Exception ex)
            {
                return ex.Message;
            }

            return strResult;
        }

        public class SignedRequestHelper
        {
            private string strAccessKeyId = string.Empty;
            private string strEndpoint = string.Empty;
            private string strAssociateTag = string.Empty;
            private byte[] strSecret;
            private const string REQUEST_URI = "/onca/xml";
            private const string REQUEST_METHOD = "GET";
            private HMAC signer;

            public SignedRequestHelper(string strAccessKeyId, string strSecret, string strEndpoint, string strAssociateTag)
            {
                this.strEndpoint = strEndpoint;
                this.strAccessKeyId = strAccessKeyId;
                this.strSecret = Encoding.UTF8.GetBytes(strSecret);
                this.strAssociateTag = strAssociateTag;
                this.signer = new HMACSHA256(this.strSecret);
            }

            // this will sign our request and create our signature
            public string Sign(IDictionary<string, string> request)
            {
                // Use a SortedDictionary to get the parameters in naturual byte order, as
                // required by AWS.
                ParamComparer pc = new ParamComparer();
                SortedDictionary<string, string> sortedMap = new SortedDictionary<string, string>(request, pc);

                // Add the AWSAccessKeyId and Timestamp to the requests.
                sortedMap["AWSAccessKeyId"] = strAccessKeyId;
                sortedMap["AssociateTag"] = strAssociateTag;
                sortedMap["Timestamp"] = this.GetTimestamp();

                // Get the canonical query string
                string canonicalQS = this.ConstructCanonicalQueryString(sortedMap);

                // Derive the bytes needs to be signed.
                StringBuilder builder = new StringBuilder();
                builder.Append(REQUEST_METHOD)
                    .Append("\n")
                    .Append(strEndpoint)
                    .Append("\n")
                    .Append(REQUEST_URI)
                    .Append("\n")
                    .Append(canonicalQS);

                string stringToSign = builder.ToString();
                byte[] toSign = Encoding.UTF8.GetBytes(stringToSign);

                // Compute the signature and convert to Base64.
                byte[] sigBytes = signer.ComputeHash(toSign);
                string signature = Convert.ToBase64String(sigBytes);

                // now construct the complete URL and return to caller.
                StringBuilder qsBuilder = new StringBuilder();
                qsBuilder.Append("http://")
                    .Append(strEndpoint)
                    .Append(REQUEST_URI)
                    .Append("?")
                    .Append(canonicalQS)
                    .Append("&Signature=")
                    .Append(this.PercentEncodeRfc3986(signature));

                return qsBuilder.ToString();
            }

            // Current time in IS0 8601 format as required by Amazon
            private string GetTimestamp()
            {
                DateTime currentTime = DateTime.UtcNow;
                string timestamp = currentTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
                return timestamp;
            }

            // 3986 percent encode string
            private string PercentEncodeRfc3986(string str)
            {
                str = HttpUtility.UrlEncode(str, System.Text.Encoding.UTF8);
                str = str.Replace("'", "%27").Replace("(", "%28").Replace(")", "%29").Replace("*", "%2A").Replace("!", "%21").Replace("%7e", "~").Replace("+", "%20");

                StringBuilder sbuilder = new StringBuilder(str);
                for (int i = 0; i < sbuilder.Length; i++)
                {
                    if (sbuilder[i] == '%')
                    {
                        if (Char.IsLetter(sbuilder[i + 1]) || Char.IsLetter(sbuilder[i + 2]))
                        {
                            sbuilder[i + 1] = Char.ToUpper(sbuilder[i + 1]);
                            sbuilder[i + 2] = Char.ToUpper(sbuilder[i + 2]);
                        }
                    }
                }
                return sbuilder.ToString();
            }

            // Consttuct the canonical query string from the sorted parameter map.
            private string ConstructCanonicalQueryString(SortedDictionary<string, string> sortedParamMap)
            {
                StringBuilder builder = new StringBuilder();

                if (sortedParamMap.Count == 0)
                {
                    builder.Append("");
                    return builder.ToString();
                }

                foreach (KeyValuePair<string, string> kvp in sortedParamMap)
                {
                    builder.Append(PercentEncodeRfc3986(kvp.Key));
                    builder.Append("=");
                    builder.Append(PercentEncodeRfc3986(kvp.Value));
                    builder.Append("&");
                }
                string canonicalString = builder.ToString();
                canonicalString = canonicalString.Substring(0, canonicalString.Length - 1);
                return canonicalString;
            }
        }

        // To help the SortedDictionary order the name-value pairs in the correct way.
        class ParamComparer : IComparer<string>
        {
            public int Compare(string p1, string p2)
            {
                return string.CompareOrdinal(p1, p2);
            }
        }
    }
}
