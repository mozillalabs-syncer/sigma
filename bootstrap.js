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

const Cu = Components.utils;
Cu.import("resource://gre/modules/AddonManager.jsm");
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

const PREF_BRANCH = "extensions.sigma.";
const SIGMA_JSON = "https://sigma.mozillalabs.com/sigma.json";
const UPDATE_FREQUENCY = 24 * 60 * 60 * 1000; // 1 day

// Keep an array of functions to call when shutting down
let unloaders = [];

// Keep an array of install ids from the manifest
let installIds = [];

XPCOMUtils.defineLazyGetter(this, "prefs", function() {
  return new Preferences(PREF_BRANCH);
});

/**
 * Disable add-ons that were installed and remember them for later
 */
function disableInstalled() {
  // Disable only enabled installed add-ons
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
 * Fetch the json manifest and install/uninstall if necessary
 */
function checkForUpdates() {
  // Skip this update if we're not online
  if (Svc.IO.offline)
    return;

  // Fetch and unpack the json data
  let res = new Resource(SIGMA_JSON);
  res.authenticator = new NoOpAuthenticator();
  let {infoUrl, install, uninstall} = res.get().obj;
  installIds = install.map(function({id}) id);

  // Only open the info page if it's different
  let oldInfo = prefs.get("infoUrl");
  if (infoUrl != oldInfo) {
    prefs.set("infoUrl", infoUrl);
    let browser = Services.wm.getMostRecentWindow("navigator:browser").gBrowser;
    browser.selectedTab = browser.addTab(infoUrl);
  }

  // Install each listed add-on if necessary
  install.forEach(function({id, url, version}) {
    AddonManager.getAddonByID(id, function(addon) {
      // Don't install if it's locally installed or newer
      if (addon != null && Svc.Version.compare(addon.version, version) >= 0)
        return;

      // Fetch the AddonInstall and install it
      AddonManager.getInstallForURL(url, function(addon) {
        if (addon == null)
          return;
        addon.install();
      }, "application/x-xpinstall");
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
}

function startup(data, reason) AddonManager.getAddonByID(data.id, function(addon) {
  Cu.import("resource://services-sync/auth.js");
  Cu.import("resource://services-sync/ext/Preferences.js");
  Cu.import("resource://services-sync/resource.js");
  Cu.import("resource://services-sync/util.js");

  if (reason == ADDON_ENABLE)
    enableDisabled();

  // Create a repeating timer that checks for updates and stops on unload
  function checker() {
    checkForUpdates();

    // Schedule the next check only if there weren't any failures
    Utils.delay(checker, UPDATE_FREQUENCY, checker, "timer");
  }
  checker();
  unloaders.push(function() checker.timer.clear());
});

function shutdown(data, reason) {
  if (reason == ADDON_DISABLE)
    disableInstalled();

  unloaders.forEach(function(unload) unload());
}
