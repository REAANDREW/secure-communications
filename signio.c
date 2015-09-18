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

#include "signio.h"
#include "charutils.h"
#endif


SignatureManager* CreateSignatureManager(){
    SignatureManager* manager = malloc(sizeof(SignatureManager*));
    manager->xsltSecPrefs = NULL;
    return manager;
};

int init(SignatureManager* signatureManager){
    /* Init libxml and libxslt libraries */
    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
    xmlIndentTreeOutput = 1; 
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
    /* disable everything */
    signatureManager->xsltSecPrefs = xsltNewSecurityPrefs(); 
    xsltSetSecurityPrefs(signatureManager->xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
    xsltSetSecurityPrefs(signatureManager->xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
    xsltSetSecurityPrefs(signatureManager->xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
    xsltSetSecurityPrefs(signatureManager->xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
    xsltSetSecurityPrefs(signatureManager->xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
    xsltSetDefaultSecurityPrefs(signatureManager->xsltSecPrefs); 
#endif /* XMLSEC_NO_XSLT */
    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr, "Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
    }

                
    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl") < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                        "that you have it installed and check shared libraries path\n"
                        "(LD_LIBRARY_PATH) envornment variable.\n");
        return(-1);     
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }
}

void shutdown(SignatureManager* signatureManager){
    /* Shutdown xmlsec-crypto library */
    xmlSecCryptoShutdown();
    
    /* Shutdown crypto library */
    xmlSecCryptoAppShutdown();
    
    /* Shutdown xmlsec library */
    xmlSecShutdown();

    /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
    xsltFreeSecurityPrefs(signatureManager->xsltSecPrefs);
    xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
    xmlCleanupParser();

    free(signatureManager);
}

/**
 * load_trusted_certs:
 * @files:              the list of filenames.
 * @files_size:         the number of filenames in #files.
 *
 * Creates simple keys manager and load trusted certificates from PEM #files.
 * The caller is responsible for destroing returned keys manager using
 * @xmlSecKeysMngrDestroy.
 *
 * Returns the pointer to newly created keys manager or NULL if an error
 * occurs.
 */
xmlSecKeysMngrPtr load_trusted_certs(char** files, int files_size) {
    xmlSecKeysMngrPtr mngr;
    int i;
        
    assert(files);
    assert(files_size > 0);
    
    /* create and initialize keys manager, we use a simple list based
     * keys manager, implement your own xmlSecKeysStore klass if you need
     * something more sophisticated 
     */
    mngr = xmlSecKeysMngrCreate();
    if(mngr == NULL) {
        fprintf(stderr, "Error: failed to create keys manager.\n");
        return(NULL);
    }
    if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        fprintf(stderr, "Error: failed to initialize keys manager.\n");
        xmlSecKeysMngrDestroy(mngr);
        return(NULL);
    }    
    
    for(i = 0; i < files_size; ++i) {
        assert(files[i]);

        /* load trusted cert */
        if(xmlSecCryptoAppKeysMngrCertLoad(mngr, files[i], xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
            fprintf(stderr,"Error: failed to load pem certificate from \"%s\"\n", files[i]);
            xmlSecKeysMngrDestroy(mngr);
            return(NULL);
        }
    }

    return(mngr);
}

/** 
 * verify_file_contents:
 * @mngr:               the pointer to keys manager.
 * @xml_file:           the signed XML file name.
 *
 * Verifies XML signature in #xml_file.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int verify(xmlSecKeysMngrPtr mngr, const char* xml_file_contents) {
    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;
    
    assert(mngr);
    assert(xml_file_contents);

    /* load file */
    //doc = xmlParseFile(xml_file_contents);
    doc = xmlReadMemory(xml_file_contents, strlen(xml_file_contents), "noname.xml", NULL, 0);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr,"Size = %ld", strlen(xml_file_contents));
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", "");
        goto done;      
    }
    
    /* find start node */
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if(node == NULL) {
        fprintf(stderr, "Error: start node not found in \"%s\"\n", "");
        goto done;      
    }

    /* create signature context */
    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* Verify signature */
    if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        fprintf(stderr,"Error: signature verify\n");
        goto done;
    }
        
    /* print verification result to stdout */
    if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
        fprintf(stdout, "Signature is OK\n");
    } else {
        fprintf(stdout, "Signature is INVALID\n");
    }    

    /* success */
    res = 0;

done:    
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }
    
    if(doc != NULL) {
        xmlFreeDoc(doc); 
    }
    return(res);
}

/** 
 * sign_file_contents:
 * @xml_file:           the XML file name.
 * @key_file:           the PEM private key file name.
 * @cert_file:          the x509 certificate PEM file.
 *
 * Signs the @xml_file using private key from @key_file and dynamicaly
 * created enveloped signature template. The certificate from @cert_file
 * is placed in the <dsig:X509Data/> node.
 *
 * Returns 0 on success or a negative value if an error occurs.
 */
int sign(const char* xml_file_contents, const char* key_file, const char* cert_file, char** output) {
    xmlDocPtr doc = NULL;
    xmlNodePtr signNode = NULL;
    xmlNodePtr refNode = NULL;
    xmlNodePtr keyInfoNode = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    int res = -1;
    
    assert(xml_file_contents);
    assert(key_file);
    assert(cert_file);

    /* load doc file */
    //doc = xmlParseFile(xml_file_contents);
    doc = xmlReadMemory(xml_file_contents, strlen(xml_file_contents), "noname.xml", NULL, 0);
    if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
        fprintf(stderr, "Error: unable to parse file \"%s\"\n", xml_file_contents);
        goto done;      
    }
    
    /* create signature template for RSA-SHA256 enveloped signature */
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId, xmlSecTransformRsaSha256Id, NULL);
    if(signNode == NULL) {
        fprintf(stderr, "Error: failed to create signature template\n");
        goto done;              
    }

    /* add <dsig:Signature/> node to the doc */
    xmlAddChild(xmlDocGetRootElement(doc), signNode);
    
    /* add reference */
    refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
                                        NULL, NULL, NULL);
    if(refNode == NULL) {
        fprintf(stderr, "Error: failed to add reference to signature template\n");
        goto done;              
    }

    /* add enveloped transform */
    if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
        fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
        goto done;              
    }
    
    /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
        fprintf(stderr, "Error: failed to add key info\n");
        goto done;              
    }
    
    if(xmlSecTmplKeyInfoAddX509Data(keyInfoNode) == NULL) {
        fprintf(stderr, "Error: failed to add X509Data node\n");
        goto done;              
    }

    /* create signature context, we don't need keys manager in this example */
    dsigCtx = xmlSecDSigCtxCreate(NULL);
    if(dsigCtx == NULL) {
        fprintf(stderr,"Error: failed to create signature context\n");
        goto done;
    }

    /* load private key, assuming that there is not password */
    dsigCtx->signKey = xmlSecCryptoAppKeyLoad(key_file, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
    if(dsigCtx->signKey == NULL) {
        fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
        goto done;
    }
    
    /* load certificate and add to the key */
    if(xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, cert_file, xmlSecKeyDataFormatPem) < 0) {
        fprintf(stderr,"Error: failed to load pem certificate \"%s\"\n", cert_file);
        goto done;
    }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, key_file) < 0) {
        fprintf(stderr,"Error: failed to set key name for key from \"%s\"\n", key_file);
        goto done;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
        fprintf(stderr,"Error: signature failed\n");
        goto done;
    }
        
    /* print signed document to stdout */
    //xmlDocDump(stdout, doc);
    xmlChar* outputXmlPtr;
    int output_size;
    /* print signed document to stdout */
    //xmlDocDump(stdout, doc);
    xmlDocDumpMemory(doc, &outputXmlPtr, &output_size);
    *output = (char*) outputXmlPtr;
    free(outputXmlPtr);
    
    /* success */
    res = 0;

done:    
    /* cleanup */
    if(dsigCtx != NULL) {
        xmlSecDSigCtxDestroy(dsigCtx);
    }
    
    if(doc != NULL) {
        xmlFreeDoc(doc); 
    }
    return(res);
}
