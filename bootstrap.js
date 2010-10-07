/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is Sigma.
 *
 * The Initial Developer of the Original Code is The Mozilla Foundation.
 * Portions created by the Initial Developer are Copyright (C) 2010
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *  Edward Lee <edilee@mozilla.com>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;
Cu.import("resource://gre/modules/AddonManager.jsm");
Cu.import("resource://gre/modules/ctypes.jsm");
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

/**
 * Sample json manifest:
 *
 * {
 *   "infoUrl": "https://site/info",
 *
 *   "install": [
 *     {
 *       "id": "addon1",
 *       "url": "https://site/addon1.xpi",
 *       "version": 1
 *     }
 *   ],
 *
 *   "uninstall": [
 *     "addon2"
 *   ]
 * }
 */

const ENCODED_PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv6S5kOB3pq3yvmXgM6ntiqjDq4YlLgiX8gQfQ/eRL3G0ubOpJE99WkErlpspQwqtZk2X+zZs2wrAqzqx/VHp+XCjlJsxfFg6lTvsXAmu1gE7FXWFaQXUgx6UURh+VuoATNHL0QOKDZxdzPRYxX+XoXMOZU/rGpRjrEri7PMvKPADTiBTNxK7BtuU/pFuNms1hb8MQXsGGV0NGtSzA0SGYHk55nGT57HNNzkseoJ9fIx1xrqTCNe5l1+OmuJ/r0BB8V/HyFkGvY0qkKp1PSS9I85BXfLuPVGXePYtdSIEYxKq2+cWmU8yOS0QkDSug9qBlBorrbs5UWDu0JTBf571bwIDAQAB";
const MAX_MANIFEST_LIFETIME = 30 * 24 * 60 * 60 * 1000; // 30 days
const MIN_CHECK_INTERVAL = 60 * 60 * 1000; // 1 hour
const PREF_BRANCH = "extensions.sigma.";
const SIGMA_FILE = "https://sigma.mozillalabs.com/sigma.";
const UPDATE_FREQUENCY = 24 * 60 * 60 * 1000; // 1 day

// Keep an array of functions to call when shutting down
let unloaders = [];

// Get a prefs reference to get and set preferences
XPCOMUtils.defineLazyGetter(this, "prefs", function() {
  return new Preferences(PREF_BRANCH);
});

/**
 * Convert base64 encoded strings into binary data
 */
XPCOMUtils.defineLazyGetter(this, "atob", function() {
  return Cc["@mozilla.org/appshell/appShellService;1"].
    getService(Ci.nsIAppShellService).hiddenDOMWindow.atob;
});

/**
 * Disable add-ons that were installed and remember them for later
 */
function disableInstalled() {
  // Disable only enabled installed add-ons
  let installIds = JSON.parse(prefs.get("installIds", "[]"));
  AddonManager.getAddonsByIDs(installIds, function(addons) {
    let disabledIds = addons.filter(function(addon) {
      if (addon == null || addon.userDisabled)
        return false;
      addon.userDisabled = true;
      return true;
    }).map(function({id}) id);

    // Save the ids for the ones that were just disabled
    prefs.set("disabledIds", JSON.stringify(disabledIds));
  });
}

/**
 * Enable add-ons that were disabled
 */
function enableDisabled() {
  // Fetch the stored ids and clear it out
  let disabledIds = JSON.parse(prefs.get("disabledIds", "[]"));
  prefs.reset("disabledIds");

  // Re-enable if it still exists
  AddonManager.getAddonsByIDs(disabledIds, function(addons) {
    addons.forEach(function(addon) {
      if (addon == null)
        return;
      addon.userDisabled = false;
    });
  });
}

/**
 * Do a GET request for the sigma file for the filetype
 */
function getSigmaFile(filetype) {
  // Use the default sigma "live" file unless we're testing against latest svn
  let url = SIGMA_FILE + filetype;
  if (prefs.get("test") == true)
    url = "http://viewvc.svn.mozilla.org/vc/projects/sigma.mozillalabs.com/trunk/sigma." + filetype + "?view=co";

  let resource = new Resource(url);
  resource.authenticator = new NoOpAuthenticator();
  return resource.get();
}

/**
 * Check that a message and signature are indeed from Mozilla
 */
XPCOMUtils.defineLazyGetter(this, "checkSignature", function() {
  // We use NSS for the crypto ops, which needs to be initialized before
  // use. By convention, PSM is required to be the module that
  // initializes NSS. So, make sure PSM is initialized in order to
  // implicitly initialize NSS.
  Cc["@mozilla.org/psm;1"].getService(Ci.nsISupports);

  // Open the NSS library.
  let nssfile = Services.dirsvc.get("GreD", Ci.nsILocalFile);
  let os = Services.appinfo.OS;
  switch (os) {
    case "WINNT":
    case "WINMO":
    case "WINCE":
      nssfile.append("nss3.dll");
      break;
    case "Darwin":
      nssfile.append("libnss3.dylib");
      break;
    case "Linux":
    case "SunOS":
    case "WebOS": // Palm Pre
      nssfile.append("libnss3.so");
      break;
    case "Android":
      // Android uses a $GREDIR/lib/ subdir.
      nssfile.append("lib");
      nssfile.append("libnss3.so");
      break;
    default:
      throw Components.Exception("unsupported platform: " + os, Cr.NS_ERROR_UNEXPECTED);
  }

  // XXX really want to be able to pass specific dlopen flags here.
  let nsslib = ctypes.open(nssfile.path);

  let nss = {};
  let nss_t = {};

  // security/nss/lib/util/seccomon.h#91
  // typedef enum
  nss_t.SECStatus = ctypes.int;
  // security/nss/lib/softoken/secmodt.h#59
  // typedef struct PK11SlotInfoStr PK11SlotInfo; (defined in secmodti.h)
  nss_t.PK11SlotInfo = ctypes.void_t;
  // security/nss/lib/util/pkcs11t.h
  nss_t.CK_OBJECT_HANDLE  = ctypes.unsigned_long;
  // security/nss/lib/util/seccomon.h#64
  // typedef enum
  nss_t.SECItemType = ctypes.int;
  // SECItemType enum values...
  nss.SIBUFFER = 0;
  // Needed for SECKEYPrivateKey struct def'n, but I don't think we need to actually access it.
  nss_t.PLArenaPool = ctypes.void_t;
  // security/nss/lib/cryptohi/keythi.h#45
  // typedef enum
  nss_t.KeyType = ctypes.int;
  // security/nss/lib/util/seccomon.h#83
  // typedef struct SECItemStr SECItem; --> SECItemStr defined right below it
  nss_t.SECItem = ctypes.StructType("SECItem",
    [{ type: nss_t.SECItemType },
     { data: ctypes.unsigned_char.ptr },
     { len : ctypes.int }]);
  // security/nss/lib/cryptohi/keythi.h#78
  // typedef struct SECKEYRSAPublicKeyStr --> def'n right above it
  nss_t.SECKEYRSAPublicKey = ctypes.StructType("SECKEYRSAPublicKey",
    [{ arena:          nss_t.PLArenaPool.ptr },
     { modulus:        nss_t.SECItem         },
     { publicExponent: nss_t.SECItem         }]);
  // security/nss/lib/cryptohi/keythi.h#189
  // typedef struct SECKEYPublicKeyStr SECKEYPublicKey; --> def'n right above it
  nss_t.SECKEYPublicKey = ctypes.StructType("SECKEYPublicKey",
    [{ arena:      nss_t.PLArenaPool.ptr    },
     { keyType:    nss_t.KeyType            },
     { pkcs11Slot: nss_t.PK11SlotInfo.ptr   },
     { pkcs11ID:   nss_t.CK_OBJECT_HANDLE   },
     { rsa:        nss_t.SECKEYRSAPublicKey } ]);
  // security/nss/lib/util/secoidt.h#52
  // typedef struct SECAlgorithmIDStr --> def'n right below it
  nss_t.SECAlgorithmID = ctypes.StructType("SECAlgorithmID",
    [{ algorithm:  nss_t.SECItem },
     { parameters: nss_t.SECItem }]);
  // security/nss/lib/certdb/certt.h#98
  // typedef struct CERTSubjectPublicKeyInfoStrA --> def'n on line 160
  nss_t.CERTSubjectPublicKeyInfo = ctypes.StructType("CERTSubjectPublicKeyInfo",
    [{ arena:            nss_t.PLArenaPool.ptr },
     { algorithm:        nss_t.SECAlgorithmID  },
     { subjectPublicKey: nss_t.SECItem         }]);


  // security/nss/lib/cryptohi/keyhi.h#165
  // CERTSubjectPublicKeyInfo * SECKEY_DecodeDERSubjectPublicKeyInfo(SECItem *spkider);
  nss.SECKEY_DecodeDERSubjectPublicKeyInfo = nsslib.declare("SECKEY_DecodeDERSubjectPublicKeyInfo",
    ctypes.default_abi, nss_t.CERTSubjectPublicKeyInfo.ptr,
    nss_t.SECItem.ptr);
  // security/nss/lib/cryptohi/keyhi.h#179
  // SECKEYPublicKey * SECKEY_ExtractPublicKey(CERTSubjectPublicKeyInfo *);
  nss.SECKEY_ExtractPublicKey = nsslib.declare("SECKEY_ExtractPublicKey",
    ctypes.default_abi, nss_t.SECKEYPublicKey.ptr,
    nss_t.CERTSubjectPublicKeyInfo.ptr);

  // security/nss/lib/pk11wrap/pk11pub.h#667
  // SECStatus PK11_Verify(SECKEYPublicKey *key, SECItem *sig,
  //                       SECItem *hash, void *wincx);
  nss.PK11_Verify = nsslib.declare("PK11_Verify",
    ctypes.default_abi, nss_t.SECStatus,
    nss_t.SECKEYPublicKey.ptr, nss_t.SECItem.ptr,
    nss_t.SECItem.ptr, ctypes.voidptr_t);

  // security/nss/lib/cryptohi/keyhi.h#193
  // extern void SECKEY_DestroyPublicKey(SECKEYPublicKey *key);
  nss.SECKEY_DestroyPublicKey = nsslib.declare("SECKEY_DestroyPublicKey",
    ctypes.default_abi, ctypes.void_t,
    nss_t.SECKEYPublicKey.ptr);
  // security/nss/lib/cryptohi/keyhi.h#58
  // extern void SECKEY_DestroySubjectPublicKeyInfo(CERTSubjectPublicKeyInfo *spki);
  nss.SECKEY_DestroySubjectPublicKeyInfo = nsslib.declare("SECKEY_DestroySubjectPublicKeyInfo",
    ctypes.default_abi, ctypes.void_t,
    nss_t.CERTSubjectPublicKeyInfo.ptr);

  function verify(message, signature, encodedPublicKey) {
    // Step 1. Get rid of the base64 encoding on the inputs.
    let pubKeyData = makeSECItem(encodedPublicKey, true);
    let signatureData = makeSECItem(signature, true);
    let plaintext = makeSECItem(Utils.sha1(message), false);

    let pubKeyInfo, pubKey;
    try {
      // Can't just do this directly, it's expecting a minimal ASN1 blob
      // pubKey = SECKEY_ImportDERPublicKey(&pubKeyData, CKK_RSA);
      pubKeyInfo = nss.SECKEY_DecodeDERSubjectPublicKeyInfo(pubKeyData.address());
      if (pubKeyInfo.isNull())
        throw Components.Exception("SECKEY_DecodeDERSubjectPublicKeyInfo failed", Cr.NS_ERROR_FAILURE);

      pubKey = nss.SECKEY_ExtractPublicKey(pubKeyInfo);
      if (pubKey.isNull())
        throw Components.Exception("SECKEY_ExtractPublicKey failed", Cr.NS_ERROR_FAILURE);

      return !nss.PK11_Verify(pubKey, signatureData.address(), plaintext.address(), null); // wincx
    } finally {
      if (pubKey && !pubKey.isNull())
        nss.SECKEY_DestroyPublicKey(pubKey);
      if (pubKeyInfo && !pubKeyInfo.isNull())
        nss.SECKEY_DestroySubjectPublicKeyInfo(pubKeyInfo);
    }
  }

  // Compress a JS string (2-byte chars) into a normal C string (1-byte chars)
  // EG, for "ABC",  0x0041, 0x0042, 0x0043 --> 0x41, 0x42, 0x43
  function byteCompress(jsString, charArray) {
    let intArray = ctypes.cast(charArray, ctypes.uint8_t.array(charArray.length));
    for (let i = 0; i < jsString.length; i++)
      intArray[i] = jsString.charCodeAt(i);
  }

  function makeSECItem(input, isEncoded) {
    if (isEncoded)
      input = atob(input);
    let outputData = new ctypes.ArrayType(ctypes.unsigned_char, input.length)();
    byteCompress(input, outputData);
    return new nss_t.SECItem(nss.SIBUFFER, outputData, outputData.length);
  }

  return function checkSignature(message, signature) {
    return verify(message, signature, ENCODED_PUBKEY);
  };
});

/**
 * Fetch the json manifest and install/uninstall if necessary
 */
function checkForUpdates() {
  // Skip this update if we're not online
  if (Svc.IO.offline)
    return;

  // Avoid multiple checks that are close to each other
  let now = Date.now();
  let lastCheck = checkForUpdates.lastCheck;
  if (lastCheck != null && now - lastCheck < MIN_CHECK_INTERVAL)
    return;
  checkForUpdates.lastCheck = now;

  // No need to fetch the manifest if the signature is the same
  let signature = getSigmaFile("sig");
  if (signature == prefs.get("signature"))
    return;

  // Fetch the json manifest and check that the signature matches
  let manifest = getSigmaFile("json");
  try {
    if (!checkSignature(manifest, signature)) {
      Cu.reportError("Sigma signature mismatch!");
      return;
    }
  }
  catch(ex) {
    Cu.reportError("Sigma signature check failure: '" + signature + "' " + ex);
    return;
  }

  // Unpack the data now that we know it's from Mozilla
  let {infoUrl, install, timestamp, uninstall} = manifest.obj;

  // Make sure the manifest includes the time it was created
  let newTime = new Date(timestamp);
  if (isNaN(newTime)) {
    Cu.reportError("Sigma timestamp missing!");
    return;
  }
  // Ignore manifests that are too old
  else if (newTime < new Date(Date.now() - MAX_MANIFEST_LIFETIME)) {
    Cu.reportError("Sigma timestamp expired!");
    return;
  }

  // Make sure this new manifest has a newer timestamp
  let oldTime = new Date(prefs.get("timestamp", 0));
  if (newTime <= oldTime) {
    Cu.reportError("Sigma timestamp misordering!");
    return;
  }

  // Only open the info page if it's different
  let oldInfo = prefs.get("infoUrl");
  if (infoUrl != oldInfo) {
    prefs.set("infoUrl", infoUrl);
    let browser = Services.wm.getMostRecentWindow("navigator:browser").gBrowser;
    browser.selectedTab = browser.addTab(infoUrl);
  }

  // Install each listed add-on if necessary
  install.forEach(function({hash, id, url, version}) {
    AddonManager.getAddonByID(id, function(addon) {
      // Don't install if it's locally installed or newer
      if (addon != null && Svc.Version.compare(addon.version, version) >= 0)
        return;

      // Make sure we have a valid hash algorithm with hex output
      if (typeof hash != "string" || hash.search(/^[^:]+:[0-9a-f]+/) != 0) {
        Cu.reportError("Sigma xpi hash malformation!");
        return;
      }

      // Fetch the AddonInstall and install it
      AddonManager.getInstallForURL(url, function(install) {
        if (install == null)
          return;
        install.install();
      }, "application/x-xpinstall", hash);
    });
  });

  // Uninstall each listed add-on id
  uninstall.forEach(function(id) {
    AddonManager.getAddonByID(id, function(addon) {
      if (addon == null)
        return;
      addon.uninstall();
    });
  });

  // Save the various values from the current manifest now everything succeeded
  let installIds = install.map(function({id}) id);
  prefs.set("installIds", JSON.stringify(installIds));
  prefs.set("signature", signature);
  prefs.set("timestamp", timestamp);
}

/**
 * Watch for add-on manager updating add-ons to also check for updates
 */
function observeAddonUpdates() {
  Cu.import("resource://gre/modules/AddonUpdateChecker.jsm");
  let orig = AddonUpdateChecker.checkForUpdates;
  AddonUpdateChecker.checkForUpdates = function() {
    // Don't block the original call and check for updates after it finishes
    Utils.delay(function() checkForUpdates());
    return orig.apply(this, arguments);
  };
  unloaders.push(function() AddonUpdateChecker.checkForUpdates = orig);
}

/**
 * Create a repeating timer that checks for updates and stops on unload
 */
function preparePeriodicUpdates() {
  function checker() {
    checkForUpdates();

    // Schedule the next check only if there weren't any failures
    Utils.delay(checker, UPDATE_FREQUENCY, checker, "timer");
  }
  checker();
  unloaders.push(function() checker.timer.clear());
}

/**
 * Handle the add-on being activated on install/enable
 */
function startup(data, reason) AddonManager.getAddonByID(data.id, function(addon) {
  Cu.import("resource://services-sync/auth.js");
  Cu.import("resource://services-sync/ext/Preferences.js");
  Cu.import("resource://services-sync/resource.js");
  Cu.import("resource://services-sync/util.js");

  if (reason == ADDON_ENABLE)
    enableDisabled();

  observeAddonUpdates();
  preparePeriodicUpdates();
});

/**
 * Handle the add-on being deactivated on uninstall/disable
 */
function shutdown(data, reason) {
  if (reason == ADDON_DISABLE)
    disableInstalled();

  unloaders.forEach(function(unload) unload());
}
