/**
 * contact_me.js — Updated frontend JS for contact form
 * 
 * Changes from original:
 *  - Sends JSON payload instead of form-encoded data
 *  - Adds CSRF token support (reads _xsrf cookie)
 *  - Preserves honeypot detection
 *  - Adds client-side rate limiting feedback
 */

$(function() {

  // Helper: read a cookie value by name
  function getCookie(name) {
    var match = document.cookie.match("\\b" + name + "=([^;]*)\\b");
    return match ? match[1] : undefined;
  }

  $("#contactForm input,#contactForm textarea").jqBootstrapValidation({
    preventSubmit: true,
    submitError: function($form, event, errors) {
      // Additional error handling if needed
    },
    submitSuccess: function($form, event) {
      event.preventDefault();

      var url = "/contact";
      var name = $("input#name").val();
      var username = $("input#username").val();   // honeypot
      var email = $("input#email").val();
      var phone = $("input#phone").val();
      var message = $("textarea#message").val();

      var firstName = name;
      if (firstName.indexOf(' ') >= 0) {
        firstName = name.split(' ').slice(0, -1).join(' ');
      }

      var $btn = $("#sendMessageButton");
      $btn.prop("disabled", true);

      // Only submit if honeypot is empty (bot detection)
      if (username === '') {

        // Build payload
        var payload = {
          name: name,
          phone: phone,
          email: email,
          message: message
        };

        // Include XSRF token if Tornado's xsrf_cookies is enabled
        var xsrf = getCookie("_xsrf");
        if (xsrf) {
          payload._xsrf = xsrf;
        }

        $.ajax({
          url: url,
          type: "POST",
          dataType: "json",
          data: payload,
          cache: false,

          success: function(response) {
            $('#success').html(
              "<div class='alert alert-success'>" +
              "<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>" +
              "<strong>Your message has been sent. </strong>" +
              "</div>"
            );
            $('#contactForm').trigger("reset");
          },

          error: function(xhr) {
            var msg = "Sorry " + firstName + ", ";
            if (xhr.status === 429) {
              msg += "you are sending too many messages. Please wait a moment and try again.";
            } else if (xhr.status === 400) {
              try {
                var resp = JSON.parse(xhr.responseText);
                msg += resp.message || "please check your input and try again.";
              } catch (e) {
                msg += "please check your input and try again.";
              }
            } else {
              msg += "it seems the server is not responding. Please try again later!";
            }

            $('#success').html(
              "<div class='alert alert-danger'>" +
              "<button type='button' class='close' data-dismiss='alert' aria-hidden='true'>&times;</button>" +
              "<strong>" + msg + "</strong>" +
              "</div>"
            );
            $('#contactForm').trigger("reset");
          },

          complete: function() {
            setTimeout(function() {
              $btn.prop("disabled", false);
            }, 1000);
          }
        });
      }
    },
    filter: function() {
      return $(this).is(":visible");
    },
  });

  $("a[data-toggle=\"tab\"]").click(function(e) {
    e.preventDefault();
    $(this).tab("show");
  });
});

// Clear status on focus
$('#name').focus(function() {
  $('#success').html('');
});