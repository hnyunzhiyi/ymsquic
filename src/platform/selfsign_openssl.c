/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    OpenSSL implementation for generating the self-signed certificate.

--*/

#define QUIC_TEST_APIS 1
#define _CRT_SECURE_NO_WARNINGS

#include "platform_internal.h"
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#endif

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/ec.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/pem.h"

#ifdef _WIN32
#pragma warning(pop)
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

//
// Generates a self signed cert using low level OpenSSL APIs.
//
QUIC_STATUS
QuicTlsGenerateSelfSignedCert(
    _In_z_ char *CertFileName,
    _In_z_ char *PrivateKeyFileName,
    _In_z_ char *SNI
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    EVP_PKEY *PKey = NULL;
    EVP_PKEY_CTX * EcKeyCtx = NULL;
    X509 *X509 = NULL;
    X509_NAME *Name = NULL;
    FILE *Fd = NULL;

    PKey = EVP_PKEY_new();

    if (PKey == NULL) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "EVP_PKEY_new() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    EcKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EcKeyCtx == NULL) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "EVP_PKEY_CTX_new_id() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen_init(EcKeyCtx);
    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "EVP_PKEY_keygen_init() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen(EcKeyCtx, &PKey);
    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "EVP_PKEY_keygen() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509 = X509_new();

    if (X509 == NULL) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "X509_new() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = ASN1_INTEGER_set(X509_get_serialNumber(X509), 1);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "ASN1_INTEGER_set() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509_gmtime_adj(X509_get_notBefore(X509), 0);
    X509_gmtime_adj(X509_get_notAfter(X509), 31536000L);

    X509_set_pubkey(X509, PKey);

    Name = X509_get_subject_name(X509);

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "C",
            MBSTRING_ASC,
            (unsigned char *)"CA",
            -1,
            -1,
            0);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "O",
            MBSTRING_ASC,
            (unsigned char *)"Microsoft",
            -1,
            -1,
            0);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "CN",
            MBSTRING_ASC,
            (unsigned char *)SNI,
            -1,
            -1,
            0);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_set_issuer_name(X509, Name);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "X509_set_issuer_name() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_sign(X509, PKey, EVP_sha256());

    if (Ret <= 0) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "X509_sign() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Fd = fopen(PrivateKeyFileName, "wb");

    if (Fd == NULL) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "fopen() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_PrivateKey(Fd, PKey, NULL, NULL, 0, NULL, NULL);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "PEM_write_PrivateKey() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

    Fd = fopen(CertFileName, "wb");

    if (Fd == NULL) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "fopen() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_X509(Fd, X509);

    if (Ret != 1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "PEM_write_X509() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

Exit:

    if (PKey != NULL) {
        EVP_PKEY_free(PKey);
        PKey= NULL;
    }

    if (EcKeyCtx != NULL) {
        EVP_PKEY_CTX_free(EcKeyCtx);
        EcKeyCtx = NULL;
    }

    if (X509 != NULL) {
        X509_free(X509);
        X509 = NULL;
    }

    if (Fd != NULL) {
        fclose(Fd);
        Fd = NULL;
    }

    return Status;
}

static char* QuicTestCertFilename = (char*)"localhost_cert.pem";
static char* QuicTestPrivateKeyFilename = (char*)"localhost_key.pem";

#ifndef MAX_PATH
#define MAX_PATH 50
#endif

typedef struct QUIC_CREDENTIAL_CONFIG_INTERNAL {
    QUIC_CREDENTIAL_CONFIG;
    QUIC_CERTIFICATE_FILE CertFile;
#ifdef _WIN32
    char TempPath [MAX_PATH];
#else
    const char* TempDir;
#endif
    char CertFilepath[MAX_PATH];
    char PrivateKeyFilepath[MAX_PATH];

} QUIC_CREDENTIAL_CONFIG_INTERNAL;

#define TEMP_DIR_TEMPLATE "/tmp/quictest.XXXXXX"

_IRQL_requires_max_(PASSIVE_LEVEL)
const QUIC_CREDENTIAL_CONFIG*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type,
	_In_ BOOLEAN ClientCertificate
    )
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(ClientCertificate);
	
    if (ClientCertificate) {
        //
        //Client certificate is not supported on OpenSSL (yet)
        //               
        QuicTraceLogInfo(
            "[ lib] ERROR, %s.",
            "Client Certificate is not supported in OpenSSL");
        return NULL;
    }

    QUIC_CREDENTIAL_CONFIG_INTERNAL* Params =
        malloc(sizeof(QUIC_CREDENTIAL_CONFIG_INTERNAL) + sizeof(TEMP_DIR_TEMPLATE));
    if (Params == NULL) {
        return NULL;
    }

    QuicZeroMemory(Params, sizeof(*Params));
    Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Params->CertificateFile = &Params->CertFile;
    Params->CertFile.CertificateFile = Params->CertFilepath;
    Params->CertFile.PrivateKeyFile = Params->PrivateKeyFilepath;

#ifdef _WIN32

    DWORD PathStatus = GetTempPathA(sizeof(Params->TempPath), Params->TempPath);
    if (PathStatus > MAX_PATH || PathStatus <= 0) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "GetTempPathA failed");
        goto Error;
    }

    UINT TempFileStatus =
        GetTempFileNameA(
            Params->TempPath,
            "msquicopensslcert",
            0,
            Params->CertFilepath);
    if (TempFileStatus == 0) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "GetTempFileNameA Cert Path failed");
        goto Error;
    }

    TempFileStatus =
        GetTempFileNameA(
            Params->TempPath,
            "msquicopensslkey",
            0,
            Params->PrivateKeyFilepath);
    if (TempFileStatus == 0) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "GetTempFileNameA Private Key failed");
        goto Error;
    }

#else
    char* Template = (char*)(Params + 1);
    memcpy(Template, TEMP_DIR_TEMPLATE, sizeof(TEMP_DIR_TEMPLATE));

    Params->TempDir = mkdtemp(Template);
    if (Params->TempDir == NULL) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "mkdtemp failed");
        goto Error;
    }

    QuicCopyMemory(
        Params->CertFilepath,
        Params->TempDir,
        strlen(Params->TempDir));
    QuicCopyMemory(
        Params->CertFilepath + strlen(Params->TempDir),
        "/",
        1);
    QuicCopyMemory(
        Params->CertFilepath + strlen(Params->TempDir) + 1,
        QuicTestCertFilename,
        strlen(QuicTestCertFilename));
    QuicCopyMemory(
        Params->PrivateKeyFilepath,
        Params->TempDir,
        strlen(Params->TempDir));
    QuicCopyMemory(
        Params->PrivateKeyFilepath + strlen(Params->TempDir),
        "/",
        1);
    QuicCopyMemory(
        Params->PrivateKeyFilepath + strlen(Params->TempDir) + 1,
        QuicTestPrivateKeyFilename,
        strlen(QuicTestPrivateKeyFilename));
#endif

    if (QUIC_FAILED(
        QuicTlsGenerateSelfSignedCert(
            Params->CertFilepath,
            Params->PrivateKeyFilepath,
            (char *)"localhost"))) {
        goto Error;
    }

    return (QUIC_CREDENTIAL_CONFIG*)Params;

Error:

#if _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#endif
    free(Params);

    return NULL;
}

_Success_(return == TRUE)
BOOLEAN
QuicGetTestCertificate(
    _In_ QUIC_TEST_CERT_TYPE Type,
    _In_ QUIC_SELF_SIGN_CERT_TYPE StoreType,
    _In_ uint32_t CredType,
    _Out_ QUIC_CREDENTIAL_CONFIG* Params,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, _Reserved_)
        QUIC_CERTIFICATE_HASH* CertHash,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE, _Reserved_)
        QUIC_CERTIFICATE_HASH_STORE* CertHashStore,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_NONE, _Out_z_bytecap_(100))
    _When_(CredType != QUIC_CREDENTIAL_TYPE_NONE, _Reserved_)
        char Principal[100]
    )
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(StoreType);
    UNREFERENCED_PARAMETER(CredType);
    UNREFERENCED_PARAMETER(Params);
    UNREFERENCED_PARAMETER(CertHash);
    UNREFERENCED_PARAMETER(CertHashStore);
    UNREFERENCED_PARAMETER(Principal);
    return FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicFreeTestCert(
    _In_ QUIC_CREDENTIAL_CONFIG* Params
    )
{
    UNREFERENCED_PARAMETER(Params);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    )
{
    QUIC_CREDENTIAL_CONFIG_INTERNAL* Params =
        (QUIC_CREDENTIAL_CONFIG_INTERNAL*)CredConfig;

#ifdef _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#elif TARGET_OS_IOS
    UNREFERENCED_PARAMETER(CredConfig);
    UNREFERENCED_PARAMETER(Params);
#else
    char RmCmd[32] = {0};
    strncpy(RmCmd, "rm -rf ", 7 + 1);
    strncat(RmCmd, Params->TempDir, sizeof(RmCmd) - strlen(RmCmd) -1);
    if (system(RmCmd) == -1) {
        QuicTraceLogError(
            "LibraryError: [lib] ERROR, %s.",
            "Tempdir del error");
    }
#endif

    free(Params);
}
