/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.dcr.sigvalidation;

import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jwt.JwtClaimsSet;

import com.forgerock.sapi.gateway.common.jwt.JwtException;
import com.forgerock.sapi.gateway.jws.JwtDecoder;

public class DCRTestHelpers {

    public static final String JWKS_JSON = "{" +
            "    \"keys\": [" +
            "      {" +
            "        \"d\": \"hQ_2Apt_vB4EOHfBd_pAuN8EuSX2xcJ7mGYS_4bh2TJA5iqc0DfMMeTcq7AFFqXSkEsbM1MBPBWq13OGnvKwRlahEi5wA5FNWvvY7Uq-rY6G4GeHG91ueBymqH-hVhlMDGw40OCShbd5NuzeV7KBe2djzjML_A2oafVwB8iKzM3vKilAD5yCgpRWLLW7KRdPYH2IItrW4tZOwtV_w0j-gj6IsM-RRGc3djTzTKZ5A3EqIP6L0mfcvZSg1zeEkt-FfmL3ZqTLRfHyiJ4NKGn1VMudE3gQrzUzCRPDbt_rXFbLfwZ6-Abcw0AUj5dy_G6ifxHwV-wh_stwJIrxzjbJ\"," +
            "        \"e\": \"AQAB\"," +
            "        \"use\": \"tls\"," +
            "        \"kid\": \"2019589298064628828993772176118160927\"," +
            "        \"x5c\": [" +
            "          \"MIIFfzCCA2egAwIBAgIQAYT1cKtmo4yXuLMggSCeHzANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtUZXN0IFNlY3VyZSBCYW5raW5nIFJvb3QgQ0EwHhcNMjMwMTE2MTA0NzQ3WhcNMjQwMTE2MTA0NzQ3WjBEMRUwEwYDVQQDDAxBY21lIEZpbnRlY2gxKzApBgNVBGEMIlBTREdCLUZGQS01ZjU2M2U4OTc0MmIyODAwMTQ1YzdkYTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZcZA6UCeaFHhRR3fayqI/kP+IQ6zhswh7QDILElAAFy48csCNpHPKmW9alGZfVBPY7Ss8ddu+X5lIyRKInla+TSaGs1NAlR8L3HxwBDvt5bayqNOeb1NpkEhiMMPYevbx1sxiIeOhxlZoPl222cVlX5BispGCa/vtG4EkAKkIelLJ7AiQ26dIP+HLzmRNJPepkMg73qEmPL6L93U/f3SFlT3Ut3jXt3qhPUmk7AY4NoFGyl34YKZ2oQU9xsIsKYii90+2Zf1FWPqna1Re/OPKnXA0RjBeCOLoCOPyunSzXTq64n4HC1ygzgvRJ32vRqSu8TXBrzjZ98NMoj5feLctAgMBAAGjggGJMIIBhTAMBgNVHRMBAf8EAjAAMFYGA1UdIwRPME2AFGAtnQoPDZDO/Lsfe6WGHY6l4LVUoSqkKDAmMSQwIgYDVQQDDBtUZXN0IFNlY3VyZSBCYW5raW5nIFJvb3QgQ0GCCQDzZXhgPta6gDAdBgNVHQ4EFgQUnEE6TVlnzQ/wYmMEaQ8dNvN2mbUwCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMIHbBggrBgEFBQcBAwSBzjCByzAIBgYEAI5GAQEwEwYGBACORgEGMAkGBwQAjkYBBgMwCQYHBACL7EkBAjCBngYGBACBmCcCMIGTMGowKQYHBACBmCcBBAweQ2FyZCBCYXNlZCBQYXltZW50IEluc3RydW1lbnRzMB4GBwQAgZgnAQMME0FjY291bnQgSW5mb3JtYXRpb24wHQYHBACBmCcBAgwSUGF5bWVudCBJbml0aWF0aW9uDB1Gb3JnZVJvY2sgRmluYW5jaWFsIEF1dGhvcml0eQwGR0ItRkZBMA0GCSqGSIb3DQEBCwUAA4ICAQBEclgUdfr64S9be21wRw0pz/wn4zMeAYhRXu1cwLwWQUSHsR+SK5zg7q9hNVuNp2+6AKYOhopnQ/QkMoAlMqDkV54ZD+HrlwBTOvZTax4khtJkVnUP5bz6+bSlmI9CVALfhg+e7AZr3QokZjtFjR9eH/R6vE0LiqpSP4qibmN1h28bJUvxPd8xB+qkalhNOZB3bnbnRk6aLAuZhV5NIgF8YWIZ1aNHbBM/7bOCDr/wKjZxfF85hpiDVtiqjA/i53cgs86pDcM/vNyw9k2wWJKKmrdO+1NXW6FgZD/MEU5sNFm3Dxk08DAq1a44hGXF68QmMbPgwmtz0nTwVq2AuXZpmHcIbg1OHhahANX6+0Id7Fo6x2fNXSBKuGmKBUzt+ebzm7eFUXVwqhUwCa/0mpWh3zjUpAlXq1b61VjiANcZFgUKaw5fSL7e/wG6qxVEehSSSPKRMrCu8UTnwyjYO8Xs/cnpOXVHbYtxPPWqCVTRxJ9M4YrxZseLY8TNqCkH7antTegacaAiFPlPXeHlcXrA/MgRyiLlXiYwve7dM50QmMsc5Vp9lb8LxIN+B/GjZF5qJ2cYvkAWTjx0Rc/7PK3M41PJijE+kE0sH9XZB34XxC8A+8/yyteoHFYnhOMJaAagdarWTN7aBJIHhz140CNYIhzXF5T/z3kB4p1pDNxMWw==\"" +
            "        ]," +
            "        \"dp\": \"aibeWmNWeDsnbdYWhgtwuvV4BeKlTclEJX4ogKteyJyvWdg_qYhCLsvw_jhmFjITJlP0DsQ0w0mnYqGzcYmW0wSssN2Q1224iqRxuwHuCrpg2zsI7gCD1VzzQW5qDllvEiLg6xrU2AWb23IERUFN3jK1Sm-eGuKPOQoJdipIRrM\"," +
            "        \"dq\": \"jcyNL5qOfYreNw6bMNu33N2UjjpIBtI1Rbsd-_rySXw3daZpFK7LOp0XXBwkwXlra_gVwwNeA27kscJYS4PDmzB98WWpyNGvza3kPXuMlSCBM45gbrLxUOAxdD7LYJnHrGq2k6fjruvkPKj93cEmzQJIz2sYJdf_azyrmut5Xus\"," +
            "        \"n\": \"mXGQOlAnmhR4UUd32sqiP5D_iEOs4bMIe0AyCxJQABcuPHLAjaRzyplvWpRmX1QT2O0rPHXbvl-ZSMkSiJ5Wvk0mhrNTQJUfC9x8cAQ77eW2sqjTnm9TaZBIYjDD2Hr28dbMYiHjocZWaD5dttnFZV-QYrKRgmv77RuBJACpCHpSyewIkNunSD_hy85kTST3qZDIO96hJjy-i_d1P390hZU91Ld417d6oT1JpOwGODaBRspd-GCmdqEFPcbCLCmIovdPtmX9RVj6p2tUXvzjyp1wNEYwXgji6Ajj8rp0s106uuJ-BwtcoM4L0Sd9r0akrvE1wa842ffDTKI-X3i3LQ\"," +
            "        \"p\": \"ynnaabV0S59JbzavBNXTvt360wot2uZJeE8ziv4cYx7l38t_l6EikmSgzZdZZBZF2KN1DI50ZEZxvsEnT9emRI7X60YhsxzP0ZqoZcZLXJfuskugT3cokYD_0QsAPJXrY1chHlCw7oBnuN_RcT2aiDf-9yXYqfECiaeEy8putd8\"," +
            "        \"kty\": \"RSA\"," +
            "        \"x5t#S256\": \"DnuRXbjspl220DfGSI6D1JSCSmW-4aHhKAU5cy-2BOM\"," +
            "        \"q\": \"wgGLYFSk-FlKzfcWQaIwZBNPuIH3JRtsIcy_AKFY-ET393r7nj2I0VRW0fSp9Ywg4spbdV-ZmIGMQWNumcdgj8OCCG5o9zoiRnrQGF5_zvzEtyNdEShKiseU1lpOkcoeoojdE5xmKAbmgUlapkzogy18Hv8rV6dP0xYla0L7fHM\"," +
            "        \"qi\": \"HjU-5oqDgw8dDnmWtPKS-kJzlhY9-i9RJFqEApjhoqS7Wwt08hoFbeWWy-B2_iyakPenLGiNbRTnO4FkVOO9DEL7NgdE6rK8O3xir01xhUFoDa9lAOCAUuOGOSVGCD-w4JIJY045PuuwJU_IaW-cormxFAznaE1DFumL7fMJBIQ\"," +
            "        \"alg\": \"PS256\"" +
            "      }," +
            "      {" +
            "        \"d\": \"Gsdio01Lnjez1MyQYJd9GsKewK-PNXdSZKueC6OLFEAKfKxHtBZlDK8snJmNoZ-dA2ec0Q1RGcMwi3TbJVJ-ep0x8FTJwLNtrNa-_eaKyGNJY4_dFCv6Q93xdcq5PSJPJ4U3J9Zgl7u9uOuvSjp5_stQzNbMm9J2jbCoYxeR_a8bD_8glV8XOYgpkGAcAXIcShSZ3YOqPa4DnPSuppSPohc30GFEyCK6JaztzbxhQXhoonLgsweib7UQWGwxSXiHOc3sZsriTb46SgPjxINWoRRsVEuhD-8ZP-oNe1B1nevCSEVerDC3rSXwJB4SaePAoXO1l-NMY4Ex9O43lbedgQ\"," +
            "        \"e\": \"AQAB\"," +
            "        \"use\": \"sig\"," +
            "        \"kid\": \"123427661642368811043687894289622697107\"," +
            "        \"x5c\": [" +
            "          \"MIIFfzCCA2egAwIBAgIQXNtNjke6eJJCHtjGGqcEkzANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBtUZXN0IFNlY3VyZSBCYW5raW5nIFJvb3QgQ0EwHhcNMjMwMTE2MTA0NzQ2WhcNMjQwMTE2MTA0NzQ2WjBEMRUwEwYDVQQDDAxBY21lIEZpbnRlY2gxKzApBgNVBGEMIlBTREdCLUZGQS01ZjU2M2U4OTc0MmIyODAwMTQ1YzdkYTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwyRgMXGfmdBJUEzHwTpg7XySS5TuIz6RyGnYIuC/ajSZzHQZbxKia4IFKp2eJg+XJgtROkCx08koV309WY9YIIxh5zwqc1KXiOwAvxjwjzfQchF21n4VMUWQ7V0gjP2U98lNlR0ScYSGT0tzTvJ5VFzC7lvZ35puHtgibqeqYeuH8bA1Vdu3/NgLhs8XeFcg38JVEdP1hXmeup5qTPKztUUPxKD0kgyGzy2Vel137DeX201GJqaxzpjlzJTK77WB+oc0Zto8bZryLIqBA7nMjaWu9HiV0TXoQiOUm67D6BAPBI1x9JWMFZnkKCpt24JucYVZtKJ0qtDtlM6KacQmrAgMBAAGjggGJMIIBhTAMBgNVHRMBAf8EAjAAMFYGA1UdIwRPME2AFGAtnQoPDZDO/Lsfe6WGHY6l4LVUoSqkKDAmMSQwIgYDVQQDDBtUZXN0IFNlY3VyZSBCYW5raW5nIFJvb3QgQ0GCCQDzZXhgPta6gDAdBgNVHQ4EFgQUAJ3B759BidNZwYS5F/LDzFaBR30wCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMIHbBggrBgEFBQcBAwSBzjCByzAIBgYEAI5GAQEwEwYGBACORgEGMAkGBwQAjkYBBgIwCQYHBACL7EkBAjCBngYGBACBmCcCMIGTMGowKQYHBACBmCcBBAweQ2FyZCBCYXNlZCBQYXltZW50IEluc3RydW1lbnRzMB4GBwQAgZgnAQMME0FjY291bnQgSW5mb3JtYXRpb24wHQYHBACBmCcBAgwSUGF5bWVudCBJbml0aWF0aW9uDB1Gb3JnZVJvY2sgRmluYW5jaWFsIEF1dGhvcml0eQwGR0ItRkZBMA0GCSqGSIb3DQEBCwUAA4ICAQBOFlkq8OlVq3E5YIEUFwKX2WJVavmbrNe2/GgZH6Tgppu32R++5Kl5+GMyxAWw+NEC1Oa9XC21jYfvXmQI0AMXjE47bzqZUMLUVeerlmyVovSq//edj00/YC8Yy2wl3dn7SOHAUt4hTW9arb1u09TwOEUXgMXIzyNp1XJGWetRC/jsoJ3XUiAuZssq+6UTg9w/D/sFLK5wp7za+DoAtI8kslaX+auMo38ByEwhhw+mTA9Xl45dyxkI9NH/Ym+ktPbKAWVrMzzLPZ8nqlb53XPJNWwUzrnaEl4VezVcZCKzTcHfipgLBl1JY4FmUNKqX8S65YUngynSQhyAjE1b/nI63hL9mhsYrAeijp3lPCMCTUnjd4xqrY5G79oA+9Uc6vZJcAanKFxw5e1i4uIfJctX3lNTgo+8L8FTmGI1Robq4nBRXJcv1kdsxyVTEjDYzvzYcQG0nDguOXg2YxEuZQWpougjPvGa+KBoxsJN1JDd91IKUAKuymBURvRuh891Nx/yjeSleEsR7qx8pPfiep5lr2MhgEc53FuMhikfst3spY4zh+vJYxPvNSdobDbDgqbhnbSFAIVfPSak2zPoRCnN9EVhU1gPmWjLVxLfSSsfVjB8hT+5Ue3LEhZ+amLt1bzdPBS1SnVNeqEHg76073UJ+ASWZBRLBZrQfupho6h5Hw==\"" +
            "        ]," +
            "        \"dp\": \"BKfs1e4lhgmU402r_jFYXsWdUnwG9VGHvF9c7NBqTyGvtSqQqo-qtGGvi2O4zDO-0mOiX0m2TrQicI9q-TWiTY3L0AMqKZ5FJ31NNvoYPi_k6trQIqazZTQ12ny11QjA17TDsxZg_rSjYPpkgT7Ds9PnDtSzcvK_KybomY7knIc\"," +
            "        \"dq\": \"ngRzC7Z28K16arXlHk2FfkjZXId1nocKL7c9pV3twEJHRwEhrtSHfYhZPtss9SJ6xrZSbMNv39jdoyxpntPUU3qoCoUfkFhiXG59sz4ZqkCvJxY6JB0QsT-Ymq1wRfBYrUbYZjztwXZC5XXBSexePP18TJAcIhTUekyog9Y_zKE\"," +
            "        \"n\": \"8MkYDFxn5nQSVBMx8E6YO18kkuU7iM-kchp2CLgv2o0mcx0GW8SomuCBSqdniYPlyYLUTpAsdPJKFd9PVmPWCCMYec8KnNSl4jsAL8Y8I830HIRdtZ-FTFFkO1dIIz9lPfJTZUdEnGEhk9Lc07yeVRcwu5b2d-abh7YIm6nqmHrh_GwNVXbt_zYC4bPF3hXIN_CVRHT9YV5nrqeakzys7VFD8Sg9JIMhs8tlXpdd-w3l9tNRiamsc6Y5cyUyu-1gfqHNGbaPG2a8iyKgQO5zI2lrvR4ldE16EIjlJuuw-gQDwSNcfSVjBWZ5CgqbduCbnGFWbSidKrQ7ZTOimnEJqw\"," +
            "        \"p\": \"-X_J9v7WzV3CpQ_4b6OZCdW8noeGCbslB45mmsJ8PfVKfNAHxXWxuVTCeavkWopdzdu8yqQF8rIpl088NOBKWTEO0lz5rMfasMM8Ii8ksLInglnL-eU3c0Dm0XB47yrilPRc6Fz0tt68TxNb0PWF4Vs9fBO8G0C0ae7IoKcS7Us\"," +
            "        \"kty\": \"RSA\"," +
            "        \"x5t#S256\": \"h22f205BjRzhHP2oRiy2EF7JRc5uaF_cQwjIcyTRvBE\"," +
            "        \"q\": \"9w8u4wSQ7vHhZ06YCVkcSCEftiGK0Bq63SFAGZMmcldYCE71n5qCvuB14_6U-8njgrWNgb-356xKQ91dPFGKIw_blUzcaNNUUPz0CL6T9TEz9BZDNPa9eZq3LApA_XtBXTzCdpmMxQvYITpMf4fbqFijGh-afEoiR_aWZs2IeSE\"," +
            "        \"qi\": \"H16bYQDTsH3l6uehhhmV1UBA_djYf0s9yOxX2T67CmVQuzVmB5GG3C-a-Q8nZA0vrmlrBYedk6hXnsjY60vlS0OnSJYBfRUnHj0iQzmCVMLHaBEP0dctQhRuDKH4Ibj6MB2iJ-2aBYm4CClza_l_Wkyh16Ur8bjl2D7sOhpa7kg\"," +
            "        \"alg\": \"PS256\"" +
            "      }" +
            "    ]" +
            "  }";
    public static final String VALID_SSA_FROM_IG = "eyJ0eXAiOiJKV1QiLCJraWQiOiJqd3Qtc2lnbmVyIiwiYWxnIjoiUFMyNTYifQ." +
            "eyJzb2Z0d2FyZV9tb2RlIjoiVEVTVCIsInNvZnR3YXJlX3JlZGlyZWN0X3VyaXMiOiJodHRwczovL3d3dy5nb29nbGUuY29tIiwib3Jn" +
            "X3N0YXR1cyI6IkFjdGl2ZSIsInNvZnR3YXJlX2NsaWVudF9uYW1lIjoiQnJpbmRsZXkgRGFzaGJvYXJkIiwic29mdHdhcmVfY2xpZW50" +
            "X2lkIjoiMTExMTExMTEiLCJpc3MiOiJ0ZXN0LXB1Ymxpc2hlciIsInNvZnR3YXJlX3Rvc191cmkiOiJodHRwczovL215YXBwL3RvcyIs" +
            "InNvZnR3YXJlX2NsaWVudF9kZXNjcmlwdGlvbiI6IkJyaW5kbGV5IEZpbmFuY2lhbCBEYXNoYm9hcmQiLCJzb2Z0d2FyZV9wb2xpY3lf" +
            "dXJpIjoiaHR0cHM6Ly9teWFwcC9wb2xpY3kiLCJzb2Z0d2FyZV9pZCI6InNvZnR3YXJlaWQiLCJvcmdfaWQiOiI1ZjU2M2U4OTc0MmIy" +
            "ODAwMTQ1YzdkYTEiLCJzb2Z0d2FyZV9sb2dvX3VyaSI6Imh0dHBzOi8vYWNtZS1tdXNpYy5jb20vd3AtY29udGVudC91cGxvYWRzLzIw" +
            "MjAvMDcvYWNtZS5wbmciLCJzb2Z0d2FyZV9qd2tzIjp7ImtleXMiOlt7ImQiOiJoUV8yQXB0X3ZCNEVPSGZCZF9wQXVOOEV1U1gyeGNK" +
            "N21HWVNfNGJoMlRKQTVpcWMwRGZNTWVUY3E3QUZGcVhTa0VzYk0xTUJQQldxMTNPR252S3dSbGFoRWk1d0E1Rk5XdnZZN1VxLXJZNkc0" +
            "R2VIRzkxdWVCeW1xSC1oVmhsTURHdzQwT0NTaGJkNU51emVWN0tCZTJkanpqTUxfQTJvYWZWd0I4aUt6TTN2S2lsQUQ1eUNncFJXTExX" +
            "N0tSZFBZSDJJSXRyVzR0Wk93dFZfdzBqLWdqNklzTS1SUkdjM2RqVHpUS1o1QTNFcUlQNkwwbWZjdlpTZzF6ZUVrdC1GZm1MM1pxVExS" +
            "Zkh5aUo0TktHbjFWTXVkRTNnUXJ6VXpDUlBEYnRfclhGYkxmd1o2LUFiY3cwQVVqNWR5X0c2aWZ4SHdWLXdoX3N0d0pJcnh6amJKIiwi" +
            "ZSI6IkFRQUIiLCJ1c2UiOiJ0bHMiLCJraWQiOiIyMDE5NTg5Mjk4MDY0NjI4ODI4OTkzNzcyMTc2MTE4MTYwOTI3IiwieDVjIjpbIk1J" +
            "SUZmekNDQTJlZ0F3SUJBZ0lRQVlUMWNLdG1vNHlYdUxNZ2dTQ2VIekFOQmdrcWhraUc5dzBCQVFzRkFEQW1NU1F3SWdZRFZRUUREQnRV" +
            "WlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVuSUZKdmIzUWdRMEV3SGhjTk1qTXdNVEUyTVRBME56UTNXaGNOTWpRd01URTJNVEEwTnpRM1dq" +
            "QkVNUlV3RXdZRFZRUUREQXhCWTIxbElFWnBiblJsWTJneEt6QXBCZ05WQkdFTUlsQlRSRWRDTFVaR1FTMDFaalUyTTJVNE9UYzBNbUl5" +
            "T0RBd01UUTFZemRrWVRFd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUNaY1pBNlVDZWFGSGhSUjNmYXlx" +
            "SS9rUCtJUTZ6aHN3aDdRRElMRWxBQUZ5NDhjc0NOcEhQS21XOWFsR1pmVkJQWTdTczhkZHUrWDVsSXlSS0lubGErVFNhR3MxTkFsUjhM" +
            "M0h4d0JEdnQ1YmF5cU5PZWIxTnBrRWhpTU1QWWV2Yngxc3hpSWVPaHhsWm9QbDIyMmNWbFg1QmlzcEdDYS92dEc0RWtBS2tJZWxMSjdB" +
            "aVEyNmRJUCtITHptUk5KUGVwa01nNzNxRW1QTDZMOTNVL2YzU0ZsVDNVdDNqWHQzcWhQVW1rN0FZNE5vRkd5bDM0WUtaMm9RVTl4c0lz" +
            "S1lpaTkwKzJaZjFGV1BxbmExUmUvT1BLblhBMFJqQmVDT0xvQ09QeXVuU3pYVHE2NG40SEMxeWd6Z3ZSSjMydlJxU3U4VFhCcnpqWjk4" +
            "Tk1vajVmZUxjdEFnTUJBQUdqZ2dHSk1JSUJoVEFNQmdOVkhSTUJBZjhFQWpBQU1GWUdBMVVkSXdSUE1FMkFGR0F0blFvUERaRE8vTHNm" +
            "ZTZXR0hZNmw0TFZVb1Nxa0tEQW1NU1F3SWdZRFZRUUREQnRVWlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVuSUZKdmIzUWdRMEdDQ1FEelpY" +
            "aGdQdGE2Z0RBZEJnTlZIUTRFRmdRVW5FRTZUVmxuelEvd1ltTUVhUThkTnZOMm1iVXdDd1lEVlIwUEJBUURBZ2VBTUJNR0ExVWRKUVFN" +
            "TUFvR0NDc0dBUVVGQndNQ01JSGJCZ2dyQmdFRkJRY0JBd1NCempDQnl6QUlCZ1lFQUk1R0FRRXdFd1lHQkFDT1JnRUdNQWtHQndRQWpr" +
            "WUJCZ013Q1FZSEJBQ0w3RWtCQWpDQm5nWUdCQUNCbUNjQ01JR1RNR293S1FZSEJBQ0JtQ2NCQkF3ZVEyRnlaQ0JDWVhObFpDQlFZWGx0" +
            "Wlc1MElFbHVjM1J5ZFcxbGJuUnpNQjRHQndRQWdaZ25BUU1NRTBGalkyOTFiblFnU1c1bWIzSnRZWFJwYjI0d0hRWUhCQUNCbUNjQkFn" +
            "d1NVR0Y1YldWdWRDQkpibWwwYVdGMGFXOXVEQjFHYjNKblpWSnZZMnNnUm1sdVlXNWphV0ZzSUVGMWRHaHZjbWwwZVF3R1IwSXRSa1pC" +
            "TUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFCRWNsZ1VkZnI2NFM5YmUyMXdSdzBwei93bjR6TWVBWWhSWHUxY3dMd1dRVVNIc1IrU0s1" +
            "emc3cTloTlZ1TnAyKzZBS1lPaG9wblEvUWtNb0FsTXFEa1Y1NFpEK0hybHdCVE92WlRheDRraHRKa1ZuVVA1Yno2K2JTbG1JOUNWQUxm" +
            "aGcrZTdBWnIzUW9rWmp0RmpSOWVIL1I2dkUwTGlxcFNQNHFpYm1OMWgyOGJKVXZ4UGQ4eEIrcWthbGhOT1pCM2JuYm5SazZhTEF1WmhW" +
            "NU5JZ0Y4WVdJWjFhTkhiQk0vN2JPQ0RyL3dLalp4ZkY4NWhwaURWdGlxakEvaTUzY2dzODZwRGNNL3ZOeXc5azJ3V0pLS21yZE8rMU5Y" +
            "VzZGZ1pEL01FVTVzTkZtM0R4azA4REFxMWE0NGhHWEY2OFFtTWJQZ3dtdHowblR3VnEyQXVYWnBtSGNJYmcxT0hoYWhBTlg2KzBJZDdG" +
            "bzZ4MmZOWFNCS3VHbUtCVXp0K2Viem03ZUZVWFZ3cWhVd0NhLzBtcFdoM3pqVXBBbFhxMWI2MVZqaUFOY1pGZ1VLYXc1ZlNMN2Uvd0c2" +
            "cXhWRWVoU1NTUEtSTXJDdThVVG53eWpZTzhYcy9jbnBPWFZIYll0eFBQV3FDVlRSeEo5TTRZcnhac2VMWThUTnFDa0g3YW50VGVnYWNh" +
            "QWlGUGxQWGVIbGNYckEvTWdSeWlMbFhpWXd2ZTdkTTUwUW1Nc2M1VnA5bGI4THhJTitCL0dqWkY1cUoyY1l2a0FXVGp4MFJjLzdQSzNN" +
            "NDFQSmlqRStrRTBzSDlYWkIzNFh4QzhBKzgveXl0ZW9IRlluaE9NSmFBYWdkYXJXVE43YUJKSUhoejE0MENOWUloelhGNVQvejNrQjRw" +
            "MXBETnhNV3c9PSJdLCJkcCI6ImFpYmVXbU5XZURzbmJkWVdoZ3R3dXZWNEJlS2xUY2xFSlg0b2dLdGV5Snl2V2RnX3FZaENMc3Z3X2po" +
            "bUZqSVRKbFAwRHNRMHcwbW5ZcUd6Y1ltVzB3U3NzTjJRMTIyNGlxUnh1d0h1Q3JwZzJ6c0k3Z0NEMVZ6elFXNXFEbGx2RWlMZzZ4clUy" +
            "QVdiMjNJRVJVRk4zaksxU20tZUd1S1BPUW9KZGlwSVJyTSIsImRxIjoiamN5Tkw1cU9mWXJlTnc2Yk1OdTMzTjJVampwSUJ0STFSYnNk" +
            "LV9yeVNYdzNkYVpwRks3TE9wMFhYQndrd1hscmFfZ1Z3d05lQTI3a3NjSllTNFBEbXpCOThXV3B5Tkd2emEza1BYdU1sU0NCTTQ1Z2Jy" +
            "THhVT0F4ZEQ3TFlKbkhyR3EyazZmanJ1dmtQS2o5M2NFbXpRSkl6MnNZSmRmX2F6eXJtdXQ1WHVzIiwibiI6Im1YR1FPbEFubWhSNFVV" +
            "ZDMyc3FpUDVEX2lFT3M0Yk1JZTBBeUN4SlFBQmN1UEhMQWphUnp5cGx2V3BSbVgxUVQyTzByUEhYYnZsLVpTTWtTaUo1V3ZrMG1ock5U" +
            "UUpVZkM5eDhjQVE3N2VXMnNxalRubTlUYVpCSVlqREQySHIyOGRiTVlpSGpvY1pXYUQ1ZHR0bkZaVi1RWXJLUmdtdjc3UnVCSkFDcENI" +
            "cFN5ZXdJa051blNEX2h5ODVrVFNUM3FaRElPOTZoSmp5LWlfZDFQMzkwaFpVOTFMZDQxN2Q2b1QxSnBPd0dPRGFCUnNwZC1HQ21kcUVG" +
            "UGNiQ0xDbUlvdmRQdG1YOVJWajZwMnRVWHZ6anlwMXdORVl3WGdqaTZBamo4cnAwczEwNnV1Si1Cd3Rjb000TDBTZDlyMGFrcnZFMXdh" +
            "ODQyZmZEVEtJLVgzaTNMUSIsInAiOiJ5bm5hYWJWMFM1OUpiemF2Qk5YVHZ0MzYwd290MnVaSmVFOHppdjRjWXg3bDM4dF9sNkVpa21T" +
            "Z3paZFpaQlpGMktOMURJNTBaRVp4dnNFblQ5ZW1SSTdYNjBZaHN4elAwWnFvWmNaTFhKZnVza3VnVDNjb2tZRF8wUXNBUEpYclkxY2hI" +
            "bEN3N29CbnVOX1JjVDJhaURmLTl5WFlxZkVDaWFlRXk4cHV0ZDgiLCJrdHkiOiJSU0EiLCJ4NXQjUzI1NiI6IkRudVJYYmpzcGwyMjBE" +
            "ZkdTSTZEMUpTQ1NtVy00YUhoS0FVNWN5LTJCT00iLCJxIjoid2dHTFlGU2stRmxLemZjV1FhSXdaQk5QdUlIM0pSdHNJY3lfQUtGWS1F" +
            "VDM5M3I3bmoySTBWUlcwZlNwOVl3ZzRzcGJkVi1abUlHTVFXTnVtY2RnajhPQ0NHNW85em9pUm5yUUdGNV96dnpFdHlOZEVTaEtpc2VV" +
            "MWxwT2tjb2Vvb2pkRTV4bUtBYm1nVWxhcGt6b2d5MThIdjhyVjZkUDB4WWxhMEw3ZkhNIiwicWkiOiJIalUtNW9xRGd3OGREbm1XdFBL" +
            "Uy1rSnpsaFk5LWk5UkpGcUVBcGpob3FTN1d3dDA4aG9GYmVXV3ktQjJfaXlha1BlbkxHaU5iUlRuTzRGa1ZPTzlERUw3TmdkRTZySzhP" +
            "M3hpcjAxeGhVRm9EYTlsQU9DQVV1T0dPU1ZHQ0QtdzRKSUpZMDQ1UHV1d0pVX0lhVy1jb3JteEZBem5hRTFERnVtTDdmTUpCSVEiLCJh" +
            "bGciOiJQUzI1NiJ9LHsiZCI6IkdzZGlvMDFMbmplejFNeVFZSmQ5R3NLZXdLLVBOWGRTWkt1ZUM2T0xGRUFLZkt4SHRCWmxESzhzbkpt" +
            "Tm9aLWRBMmVjMFExUkdjTXdpM1RiSlZKLWVwMHg4RlRKd0xOdHJOYS1fZWFLeUdOSlk0X2RGQ3Y2UTkzeGRjcTVQU0pQSjRVM0o5Wmds" +
            "N3U5dU91dlNqcDVfc3RRek5iTW05SjJqYkNvWXhlUl9hOGJEXzhnbFY4WE9ZZ3BrR0FjQVhJY1NoU1ozWU9xUGE0RG5QU3VwcFNQb2hj" +
            "MzBHRkV5Q0s2SmF6dHpieGhRWGhvb25MZ3N3ZWliN1VRV0d3eFNYaUhPYzNzWnNyaVRiNDZTZ1BqeElOV29SUnNWRXVoRC04WlAtb05l" +
            "MUIxbmV2Q1NFVmVyREMzclNYd0pCNFNhZVBBb1hPMWwtTk1ZNEV4OU80M2xiZWRnUSIsImUiOiJBUUFCIiwidXNlIjoic2lnIiwia2lk" +
            "IjoiMTIzNDI3NjYxNjQyMzY4ODExMDQzNjg3ODk0Mjg5NjIyNjk3MTA3IiwieDVjIjpbIk1JSUZmekNDQTJlZ0F3SUJBZ0lRWE50Tmpr" +
            "ZTZlSkpDSHRqR0dxY0VrekFOQmdrcWhraUc5dzBCQVFzRkFEQW1NU1F3SWdZRFZRUUREQnRVWlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVu" +
            "SUZKdmIzUWdRMEV3SGhjTk1qTXdNVEUyTVRBME56UTJXaGNOTWpRd01URTJNVEEwTnpRMldqQkVNUlV3RXdZRFZRUUREQXhCWTIxbElF" +
            "WnBiblJsWTJneEt6QXBCZ05WQkdFTUlsQlRSRWRDTFVaR1FTMDFaalUyTTJVNE9UYzBNbUl5T0RBd01UUTFZemRrWVRFd2dnRWlNQTBH" +
            "Q1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUR3eVJnTVhHZm1kQkpVRXpId1RwZzdYeVNTNVR1SXo2UnlHbllJdUMvYWpT" +
            "WnpIUVpieEtpYTRJRktwMmVKZytYSmd0Uk9rQ3gwOGtvVjMwOVdZOVlJSXhoNXp3cWMxS1hpT3dBdnhqd2p6ZlFjaEYyMW40Vk1VV1E3" +
            "VjBnalAyVTk4bE5sUjBTY1lTR1QwdHpUdko1VkZ6QzdsdlozNXB1SHRnaWJxZXFZZXVIOGJBMVZkdTMvTmdMaHM4WGVGY2czOEpWRWRQ" +
            "MWhYbWV1cDVxVFBLenRVVVB4S0Qwa2d5R3p5MlZlbDEzN0RlWDIwMUdKcWF4enBqbHpKVEs3N1dCK29jMFp0bzhiWnJ5TElxQkE3bk1q" +
            "YVd1OUhpVjBUWG9RaU9VbTY3RDZCQVBCSTF4OUpXTUZabmtLQ3B0MjRKdWNZVlp0S0owcXREdGxNNkthY1FtckFnTUJBQUdqZ2dHSk1J" +
            "SUJoVEFNQmdOVkhSTUJBZjhFQWpBQU1GWUdBMVVkSXdSUE1FMkFGR0F0blFvUERaRE8vTHNmZTZXR0hZNmw0TFZVb1Nxa0tEQW1NU1F3" +
            "SWdZRFZRUUREQnRVWlhOMElGTmxZM1Z5WlNCQ1lXNXJhVzVuSUZKdmIzUWdRMEdDQ1FEelpYaGdQdGE2Z0RBZEJnTlZIUTRFRmdRVUFK" +
            "M0I3NTlCaWROWndZUzVGL0xEekZhQlIzMHdDd1lEVlIwUEJBUURBZ2VBTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNQ01JSGJCZ2dy" +
            "QmdFRkJRY0JBd1NCempDQnl6QUlCZ1lFQUk1R0FRRXdFd1lHQkFDT1JnRUdNQWtHQndRQWprWUJCZ0l3Q1FZSEJBQ0w3RWtCQWpDQm5n" +
            "WUdCQUNCbUNjQ01JR1RNR293S1FZSEJBQ0JtQ2NCQkF3ZVEyRnlaQ0JDWVhObFpDQlFZWGx0Wlc1MElFbHVjM1J5ZFcxbGJuUnpNQjRH" +
            "QndRQWdaZ25BUU1NRTBGalkyOTFiblFnU1c1bWIzSnRZWFJwYjI0d0hRWUhCQUNCbUNjQkFnd1NVR0Y1YldWdWRDQkpibWwwYVdGMGFX" +
            "OXVEQjFHYjNKblpWSnZZMnNnUm1sdVlXNWphV0ZzSUVGMWRHaHZjbWwwZVF3R1IwSXRSa1pCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElD" +
            "QVFCT0Zsa3E4T2xWcTNFNVlJRVVGd0tYMldKVmF2bWJyTmUyL0dnWkg2VGdwcHUzMlIrKzVLbDUrR015eEFXdytORUMxT2E5WEMyMWpZ" +
            "ZnZYbVFJMEFNWGpFNDdienFaVU1MVVZlZXJsbXlWb3ZTcS8vZWRqMDAvWUM4WXkyd2wzZG43U09IQVV0NGhUVzlhcmIxdTA5VHdPRVVY" +
            "Z01YSXp5TnAxWEpHV2V0UkMvanNvSjNYVWlBdVpzc3ErNlVUZzl3L0Qvc0ZMSzV3cDd6YStEb0F0SThrc2xhWCthdU1vMzhCeUV3aGh3" +
            "K21UQTlYbDQ1ZHl4a0k5TkgvWW0ra3RQYktBV1ZyTXp6TFBaOG5xbGI1M1hQSk5Xd1V6cm5hRWw0VmV6VmNaQ0t6VGNIZmlwZ0xCbDFK" +
            "WTRGbVVOS3FYOFM2NVlVbmd5blNRaHlBakUxYi9uSTYzaEw5bWhzWXJBZWlqcDNsUENNQ1RVbmpkNHhxclk1Rzc5b0ErOVVjNnZaSmNB" +
            "YW5LRnh3NWUxaTR1SWZKY3RYM2xOVGdvKzhMOEZUbUdJMVJvYnE0bkJSWEpjdjFrZHN4eVZURWpEWXp2elljUUcwbkRndU9YZzJZeEV1" +
            "WlFXcG91Z2pQdkdhK0tCb3hzSk4xSkRkOTFJS1VBS3V5bUJVUnZSdWg4OTFOeC95amVTbGVFc1I3cXg4cFBmaWVwNWxyMk1oZ0VjNTNG" +
            "dU1oaWtmc3Qzc3BZNHpoK3ZKWXhQdk5TZG9iRGJEZ3FiaG5iU0ZBSVZmUFNhazJ6UG9SQ25OOUVWaFUxZ1BtV2pMVnhMZlNTc2ZWakI4" +
            "aFQrNVVlM0xFaForYW1MdDFiemRQQlMxU25WTmVxRUhnNzYwNzNVSitBU1daQlJMQlpyUWZ1cGhvNmg1SHc9PSJdLCJkcCI6IkJLZnMx" +
            "ZTRsaGdtVTQwMnJfakZZWHNXZFVud0c5VkdIdkY5YzdOQnFUeUd2dFNxUXFvLXF0R0d2aTJPNHpETy0wbU9pWDBtMlRyUWljSTlxLVRX" +
            "aVRZM0wwQU1xS1o1RkozMU5Odm9ZUGlfazZ0clFJcWF6WlRRMTJueTExUWpBMTdURHN4WmdfclNqWVBwa2dUN0RzOVBuRHRTemN2S19L" +
            "eWJvbVk3a25JYyIsImRxIjoibmdSekM3WjI4SzE2YXJYbEhrMkZma2paWElkMW5vY0tMN2M5cFYzdHdFSkhSd0VocnRTSGZZaFpQdHNz" +
            "OVNKNnhyWlNiTU52MzlqZG95eHBudFBVVTNxb0NvVWZrRmhpWEc1OXN6NFpxa0N2SnhZNkpCMFFzVC1ZbXExd1JmQllyVWJZWmp6dHdY" +
            "WkM1WFhCU2V4ZVBQMThUSkFjSWhUVWVreW9nOVlfektFIiwibiI6IjhNa1lERnhuNW5RU1ZCTXg4RTZZTzE4a2t1VTdpTS1rY2hwMkNM" +
            "Z3YybzBtY3gwR1c4U29tdUNCU3FkbmlZUGx5WUxVVHBBc2RQSktGZDlQVm1QV0NDTVllYzhLbk5TbDRqc0FMOFk4STgzMEhJUmR0Wi1G" +
            "VEZGa08xZElJejlsUGZKVFpVZEVuR0VoazlMYzA3eWVWUmN3dTViMmQtYWJoN1lJbTZucW1IcmhfR3dOVlhidF96WUM0YlBGM2hYSU5f" +
            "Q1ZSSFQ5WVY1bnJxZWFrenlzN1ZGRDhTZzlKSU1oczh0bFhwZGQtdzNsOXROUmlhbXNjNlk1Y3lVeXUtMWdmcUhOR2JhUEcyYThpeUtn" +
            "UU81ekkybHJ2UjRsZEUxNkVJamxKdXV3LWdRRHdTTmNmU1ZqQldaNUNncWJkdUNibkdGV2JTaWRLclE3WlRPaW1uRUpxdyIsInAiOiIt" +
            "WF9KOXY3V3pWM0NwUV80YjZPWkNkVzhub2VHQ2JzbEI0NW1tc0o4UGZWS2ZOQUh4WFd4dVZUQ2VhdmtXb3BkemR1OHlxUUY4cklwbDA4" +
            "OE5PQktXVEVPMGx6NXJNZmFzTU04SWk4a3NMSW5nbG5MLWVVM2MwRG0wWEI0N3lyaWxQUmM2RnowdHQ2OFR4TmIwUFdGNFZzOWZCTzhH" +
            "MEMwYWU3SW9LY1M3VXMiLCJrdHkiOiJSU0EiLCJ4NXQjUzI1NiI6ImgyMmYyMDVCalJ6aEhQMm9SaXkyRUY3SlJjNXVhRl9jUXdqSWN5" +
            "VFJ2QkUiLCJxIjoiOXc4dTR3U1E3dkhoWjA2WUNWa2NTQ0VmdGlHSzBCcTYzU0ZBR1pNbWNsZFlDRTcxbjVxQ3Z1QjE0XzZVLThuamdy" +
            "V05nYi0zNTZ4S1E5MWRQRkdLSXdfYmxVemNhTk5VVVB6MENMNlQ5VEV6OUJaRE5QYTllWnEzTEFwQV9YdEJYVHpDZHBtTXhRdllJVHBN" +
            "ZjRmYnFGaWpHaC1hZkVvaVJfYVdaczJJZVNFIiwicWkiOiJIMTZiWVFEVHNIM2w2dWVoaGhtVjFVQkFfZGpZZjBzOXlPeFgyVDY3Q21W" +
            "UXV6Vm1CNUdHM0MtYS1ROG5aQTB2cm1sckJZZWRrNmhYbnNqWTYwdmxTME9uU0pZQmZSVW5IajBpUXptQ1ZNTEhhQkVQMGRjdFFoUnVE" +
            "S0g0SWJqNk1CMmlKLTJhQlltNENDbHphX2xfV2t5aDE2VXI4YmpsMkQ3c09ocGE3a2ciLCJhbGciOiJQUzI1NiJ9XX0sInNvZnR3YXJl" +
            "X3JvbGVzIjpbIkRBVEEiLCJBSVNQIiwiQ0JQSUkiLCJQSVNQIl0sImV4cCI6MTY3Mzk1Mjg0NSwib3JnX25hbWUiOiJBY21lIEZpbnRl" +
            "Y2giLCJpYXQiOjE2NzM5NTI1NDV9.BiTAcnCPSQVuziVJXY8J15W2_kEbsn0RqYwFCYPjaYAeaCPXJu5d0LKvpgunUrEV9eBwPxQyFy1" +
            "FcHoTeNkJBnnq4ATSBS8AlnY9bi6D0Ur3AyeEBbQyy9bSGakw-mKSspTX8lgDzWPQVUGhmY0wIQYJ_g8bVb-leM9_T-_aiNilFJALF8-" +
            "WPGbsRxnteUc_sF9e6PD_eR80GrGpTaDqMPOdfSK0lUyEEo-eMv0Vm1MByRjINc4qF6ezHv5Vv_ENNOkY0ubKx5x3F9FeZjrYkctTpjB" +
            "U2MCAiH-Kr2zcuLzk0NpGxhMhTibz8ZhKAxTXdQuKLNiI9vaAjeyZOWL-cQ";


    /**
     * Gets a jwks value from the valid IG SSA
     * @return a JsonValue jwks set
     * @throws JwtException when the jwt can't be decoded
     */
    public static JsonValue getJwksJsonValue() {
        String b64EncodedSSA = DCRTestHelpers.VALID_SSA_FROM_IG;
        JwtDecoder jwtDecoder = new JwtDecoder();
        SignedJwt ssa = null;
        try {
            ssa = jwtDecoder.getSignedJwt(b64EncodedSSA);
        } catch (JwtException e){
            throw new IllegalArgumentException(e);
        }
        JwtClaimsSet ssaClaims = ssa.getClaimsSet();
        JsonValue jwks = ssaClaims.get("software_jwks");
        return jwks;
    }
}
