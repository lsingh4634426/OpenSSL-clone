/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/objects.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include "x509_local.h"
#include <crypto/x509.h>

/*-
 * X509_ATTRIBUTE: this has the following form:
 *
 * typedef struct x509_attributes_st
 *      {
 *      ASN1_OBJECT *object;
 *      STACK_OF(ASN1_TYPE) *set;
 *      } X509_ATTRIBUTE;
 *
 */

ASN1_SEQUENCE(X509_ATTRIBUTE) = {
        ASN1_SIMPLE(X509_ATTRIBUTE, object, ASN1_OBJECT),
        ASN1_SET_OF(X509_ATTRIBUTE, set, ASN1_ANY)
} ASN1_SEQUENCE_END(X509_ATTRIBUTE)

IMPLEMENT_ASN1_FUNCTIONS(X509_ATTRIBUTE)
IMPLEMENT_ASN1_DUP_FUNCTION(X509_ATTRIBUTE)

X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value)
{
    X509_ATTRIBUTE *ret = NULL;
    ASN1_TYPE *val = NULL;
    ASN1_OBJECT *oid;

    if ((oid = OBJ_nid2obj(nid)) == NULL)
        return NULL;
    if ((ret = X509_ATTRIBUTE_new()) == NULL)
        return NULL;
    ret->object = oid;
    if ((val = ASN1_TYPE_new()) == NULL)
        goto err;
    if (!sk_ASN1_TYPE_push(ret->set, val))
        goto err;

    ASN1_TYPE_set(val, atrtype, value);
    return ret;
 err:
    X509_ATTRIBUTE_free(ret);
    ASN1_TYPE_free(val);
    return NULL;
}

static int print_hex(BIO *out, unsigned char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (BIO_printf(out, "%02X ", buf[i]) <= 0) {
            return 0;
        }
    }
    return 1;
}

static int asn1_integer_print_bio(BIO *bio, const ASN1_INTEGER *num)
{
    BIGNUM *num_bn;
    int result = 0;
    char *hex;

    num_bn = ASN1_INTEGER_to_BN(num, NULL);
    if (num_bn == NULL)
        return -1;
    if ((hex = BN_bn2hex(num_bn)) != NULL) {
        result = BIO_write(bio, "0x", 2) > 0;
        result = result && BIO_write(bio, hex, strlen(hex)) > 0;
        OPENSSL_free(hex);
    } else {
        return -1;
    }
    BN_free(num_bn);

    return result;
}

static int print_oid(BIO *out, const ASN1_OBJECT *oid) {
    const char *ln;
    char objbuf[80];
    int rc;

    if (OBJ_obj2txt(objbuf, sizeof(objbuf), oid, 1) <= 0)
        return 0;
    ln = OBJ_nid2ln(OBJ_obj2nid(oid));
    rc = (ln != NULL)
           ? BIO_printf(out, "%s (%s)", objbuf, ln)
           : BIO_printf(out, "%s", objbuf);
    if (rc < 0)
        return 0;
    return 1;
}

int ossl_print_attribute_value(BIO *out,
                               int obj_nid,
                               const ASN1_TYPE *av,
                               int indent)
{
    ASN1_STRING *str;
    unsigned char *value;
    X509_NAME *xn = NULL;
    int64_t int_val;

    /*
     * This switch-case is only for syntaxes that are not encoded as a single
     * primitively-constructed value universal ASN.1 type.
     */
    switch (obj_nid) {
    case NID_undef: /* Unrecognized OID. */
        break;
    /* Attribute types with DN syntax. */
    case NID_member:
    case NID_roleOccupant:
    case NID_seeAlso:
    case NID_manager:
    case NID_documentAuthor:
    case NID_secretary:
    case NID_associatedName:
    case NID_dITRedirect:
    case NID_owner:
        /*
         * d2i_ functions increment the ppin pointer. See doc/man3/d2i_X509.pod.
         * This preserves the original  pointer. We don't want to corrupt this
         * value.
         */
        value = av->value.sequence->data;
        xn = d2i_X509_NAME(NULL,
                           (const unsigned char**)&value,
                           av->value.sequence->length);
        if (xn == NULL) {
            BIO_puts(out, "(COULD NOT DECODE DISTINGUISHED NAME)\n");
            return 0;
        }
        if (X509_NAME_print_ex(out, xn, indent, XN_FLAG_SEP_CPLUS_SPC) <= 0)
            return 0;
        X509_NAME_free(xn);
        return 1;

    default:
        break;
    }

    switch (av->type) {
    case V_ASN1_BOOLEAN:
        if (av->value.boolean) {
            if (BIO_printf(out, "%*sTRUE", indent, "") <= 0)
                return 0;
        } else {
            if (BIO_printf(out, "%*sFALSE", indent, "") <= 0)
                return 0;
        }
        return 1;

    case V_ASN1_INTEGER:
        if (BIO_printf(out, "%*s", indent, "") <= 0)
            return 0;
        if (ASN1_INTEGER_get_int64(&int_val, av->value.integer) > 0) {
            return BIO_printf(out, "%lld", (long long int)int_val);
        } else {
            str = av->value.integer;
            return asn1_integer_print_bio(out, str);
        }

    case V_ASN1_ENUMERATED:
        if (BIO_printf(out, "%*s", indent, "") <= 0)
            return 0;
        if (ASN1_ENUMERATED_get_int64(&int_val, av->value.enumerated) > 0) {
            return BIO_printf(out, "%lld", (long long int)int_val);
        } else {
            str = av->value.enumerated;
            return asn1_integer_print_bio(out, str);
        }

    case V_ASN1_BIT_STRING:
        if (BIO_printf(out, "%*s", indent, "") <= 0)
            return 0;
        return print_hex(out, av->value.bit_string->data,
                         av->value.bit_string->length);

    case V_ASN1_OCTET_STRING:
    case V_ASN1_VIDEOTEXSTRING:
        if (BIO_printf(out, "%*s", indent, "") <= 0)
            return 0;
        return print_hex(out, av->value.octet_string->data,
                         av->value.octet_string->length);

    case V_ASN1_NULL:
        if (BIO_printf(out, "%*sNULL", indent, "") <= 0)
            return 0;
        return 1;

    case V_ASN1_OBJECT:
        if (BIO_printf(out, "%*s", indent, "") <= 0)
            return 0;
        return print_oid(out, av->value.object);
    
    /*
     * ObjectDescriptor is an IMPLICIT GraphicString, but GeneralString is a
     * superset supported by OpenSSL, so we will use that anywhere a
     * GraphicString is needed here.
     */
    case V_ASN1_GENERALSTRING:
    case V_ASN1_GRAPHICSTRING:
    case V_ASN1_OBJECT_DESCRIPTOR:
        if (BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.generalstring->length,
                          av->value.generalstring->data) < 0)
            return 0;
        return 1;

    /* EXTERNAL would go here. */
    /* EMBEDDED PDV would go here. */

    case V_ASN1_UTF8STRING:
        if (BIO_printf(out, "%*s%.*s", indent, "",
                          av->value.utf8string->length,
                          av->value.utf8string->data) < 0)
            return 0;
        return 1;

    case V_ASN1_REAL:
        if (BIO_printf(out, "%*sREAL", indent, "") < 0)
            return 0;
        return 1;

    /* RELATIVE-OID would go here. */
    /* TIME would go here. */

    case V_ASN1_SEQUENCE:
        if (ASN1_parse_dump(out, av->value.sequence->data,
                            av->value.sequence->length, indent, 1) <= 0)
            return 0;
        return 1;

    case V_ASN1_SET:
        if (ASN1_parse_dump(out, av->value.set->data,
                               av->value.set->length, indent, 1) <= 0)
            return 0;
        return 1;

    /*
     * UTCTime ::= [UNIVERSAL 23] IMPLICIT VisibleString
     * GeneralizedTime ::= [UNIVERSAL 24] IMPLICIT VisibleString
     * VisibleString is a superset for NumericString, so it will work for that.
     */
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
    case V_ASN1_NUMERICSTRING:
        if (BIO_printf(out, "%*s%.*s", indent, "",
                       av->value.visiblestring->length,
                       av->value.visiblestring->data) <= 0)
            return 0;
        return 1;

    case V_ASN1_PRINTABLESTRING:
        if (BIO_printf(out, "%*s%.*s", indent, "",
                       av->value.printablestring->length,
                       av->value.printablestring->data) <= 0)
            return 0;
        return 1;

    case V_ASN1_T61STRING:
        if (BIO_printf(out, "%*s%.*s", indent, "",
                       av->value.t61string->length,
                       av->value.t61string->data) <= 0)
            return 0;
        return 1;

    case V_ASN1_IA5STRING:
        if (BIO_printf(out, "%*s%.*s", indent, "",
                       av->value.ia5string->length,
                       av->value.ia5string->data) <= 0)
            return 0;
        return 1;

    /* UniversalString would go here. */
    /* CHARACTER STRING would go here. */
    /* BMPString would go here. */
    /* DATE would go here. */
    /* TIME-OF-DAY would go here. */
    /* DATE-TIME would go here. */
    /* DURATION would go here. */
    /* OID-IRI would go here. */
    /* RELATIVE-OID-IRI would go here. */

    /* Would it be approriate to just hexdump? */
    default:
        if (BIO_printf(out, "%*s<Unsupported tag %d>", indent, "", av->type) <= 0)
            return 0;
        return 1;
    }
}
