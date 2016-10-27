'use strict';

// Make sure we are in strict mode.
(function() {
  var strictMode = false;
  try {
    NaN = NaN;
  } catch (err) {
    strictMode = true;
  }
  if (!strictMode) {
    throw 'Unable to activate strict mode.';
  }
})();

// The hashing difficulty.
// 2 ^ difficulty rounds of SHA-256 will be computed.
// Chrome copy2clipboard requires this to finish within 1 sec.
var difficulty = 14;

var chrometabs = typeof chrome !== 'undefined' && chrome.tabs || {
  sendMessage:   function(a,b,f) { f({type:'web'})},
  executeScript: function(a,b,f) { f()},
  query:         function(a,f)   { f([{url:'http://select domain'}])},
  isPage:       true
};

$(function() {
  // Get the current tab.
  chrometabs.query({
      active: true,
      currentWindow: true
    }, function(tabs) {
      var showError = function(err) {
        $('#domain').val('N/A').addClass('disabled');
        $('input').prop('disabled', true);
        $('select').addClass('disabled');
        $('p:not(#message)').addClass('disabled');
        $('#message').addClass('error').text(err);
      };

      // Make sure we got the tab.
      if (tabs.length !== 1) {
        return showError('Unable to determine active tab.');
      }

      // Get the domain.
      var matches = tabs[0].url.match(/^http(?:s?):\/\/(?:www\.)?([^/]*)/);
      if (!matches) {
        // Example cause: files served over the file:// protocol.
        return showError('Unable to determine the domain.');
      }
      var domain = matches[1].toLowerCase();
      if (/^http(?:s?):\/\/chrome\.google\.com\/webstore.*/.test(tabs[0].url)) {
        // Technical reason: Chrome prevents content scripts from running in the app gallery.
        return showError('Try Hashpass on another domain.');
      }
      var dom_code = (localStorage.getItem('_'+domain) || domain+'##'+$('#format').val())
                     .split('##');
      if (dom_code[0] !== domain) {
        $('#olddom').html('<strike>'+domain);
      }
      $('#domain').val(dom_code[0]);
      $('#format').val(dom_code[1]);
      var userKey = function() { return localStorage.getItem('userkey') || '';};
      $('#userkey').val(userKey().slice(0,3)+'\u2022'.repeat(Math.max(0,userKey().length-3)));
      var cookie = document.cookie.match(/1=?([^;]*)/);
      $('#key').val(localStorage.getItem('key') || cookie && atob(cookie[1]));

      // Run the content script to register the message handler.
      chrometabs.executeScript(tabs[0].id, {
        file: 'content_script.js'
      }, function() {
        // Check if a password field is selected.
        chrometabs.sendMessage(tabs[0].id, {
            type: 'hashpassCheckIfPasswordField'
          }, function(response) {
            // Different user interfaces depending on whether a password field is in focus.
            if (response && response.type === 'password') {
              $('#message').html('Press <strong><a href="#">ENTER</a></strong> to fill in the password field.');
            } else {
              chrometabs.sendMessage = function(a,b,f) {
                var textField = document.createElement('textarea');
                textField.innerText = b.hash;
                document.body.appendChild(textField);
                textField.focus();
                textField.setSelectionRange(0, textField.value.length);
                var copyOk = false;
                try {
                  copyOk = document.execCommand('copy');
                } catch(e) {}
                textField.blur();
                textField.remove();
                if (!copyOk)
                  showError('Copy to clipboard did not work')
                else if (!chrometabs.isPage)
                  f();
              };
              $('#message').html('Press <strong><a href="#">ENTER</a></strong> to copy password to Clipboard.');
            }

            var extractValue = function(bits, range) {
              var mod = 0;
              for (var b = bits.length; --b >= 0;) {
                var l = (bits[b]>>>0) * range + mod;
                mod = l / 0x100000000 >>> 0;
                bits[b] = l >>> 0;
              }
              return mod;
            }
            // Called whenever the key changes.
            var update = function() {
              // Compute the first 16 base64 characters of iterated-SHA-256(domain + '/' + key, 2 ^ difficulty).
              var key = userKey() + $('#key').val();
              var domain = $('#domain').val().replace(/^\s+|\s+$/g, '').toLowerCase();

              var rounds = Math.pow(2, difficulty);
              var bits = domain + '/' + key;
              for (var i = 0; i < rounds; i += 1) {
                bits = sjcl.hash.sha256.hash(bits);
              }
              var format = $('#format').val();
              var count  = +format.split(/[\[\]]/)[1];
              var types  = [];
              if (format.search('Az') >= 0) {
                types.push('abcdefghijklmnopqrstuvwxyz');
                types.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
              }
              if (format.search('09') >= 0) {
                types.push('0123456789');
              }
              if (format.search('!') >= 0) {
                types.push('!#$%&()*+-/:<>=?@_');
              }
              var ret = Array(count - types.length);
              var all_types = types.join('');
              for (var i = 0; i < ret.length; i++) {
                ret[i] = all_types[extractValue(bits,all_types.length)];
              }
              for (var i = 0; i < types.length; i++) {
                ret.splice(extractValue(bits,1+ret.length),0,
                           types[i][extractValue(bits,types[i].length)]);
              }
              return ret.join('');
            };

            var enterFnc = function() {
              localStorage.setItem('userkey',userKey());
              localStorage.setItem('_'+domain, $('#domain').val()+'##'+$('#format').val());
              document.cookie = '1='+btoa($('#key').val());
              // Try to fill the selected password field with the hash.
              chrometabs.sendMessage(tabs[0].id, {
                  type: 'hashpassFillPasswordField',
                  hash: update()
                }, function(response) {
                  // If successful, close the popup.
                  window.close();
                }
              );
            }
            $(document).on("click", "a", enterFnc);
            $('#userkey, #domain, #key').keydown(function(e) {
              // Listen for the Enter key.
              if (e.which === 13) {
                enterFnc();
              }
            });

            $('#userkey').bind('focus', function() {
              $('#userkey').val(localStorage.getItem('userkey'));
              $('#userkey').unbind('focus');
              userKey = function() { return $('#userkey').val(); };
              $('#userkey').focus();
            });
            // Focus the text field.
            $('#key').focus();
          }
        );
      });
    }
  );
});
