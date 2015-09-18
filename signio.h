#ifndef SIGNIO
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#endif

typedef struct SignatureManager {
    xsltSecurityPrefsPtr xsltSecPrefs;
} SignatureManager;

SignatureManager* CreateSignatureManager();

xmlSecKeysMngrPtr load_trusted_certs(char** files, int files_size);

int verify(xmlSecKeysMngrPtr mngr, const char* xml_file);

int sign(const char* xml_file, const char* key_file, const char* cert_file, char** output);

int init(SignatureManager* signatureManager);

void shutdown(SignatureManager* signatureManager);

