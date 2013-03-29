/**
 * @file
 */

(function ($) {

  Drupal.behaviors.twitter_queue_list = {

    attach: function() {
      var min = parseInt($('#countdown').html());
      var sec = 59;

      var delay = (function() {
        var timer = 0;
        return function(callback, ms) {
          clearTimeout(timer);
          timer = setTimeout(callback, ms);
        };
      })();

      /*
      @todo figureout what to do with the countdown, for the next tweet.
      countdown = setInterval(function(){
        $("#countdown").html(min + ':' + sec);
        if (sec == 0) {
          min--;
          sec = 60;
          if (min == -1) window.location = Drupal.basepath + 'admin/content/twitter-queue';
        }
        sec--;
      }, 1000);
      */

      $('#edit-textarea').bind('focus', function() {
          $(this).attr('class', 'textOn');
          if ($(this).val() == Drupal.t("What's happening?")) $(this).val('');

      });
      $('#edit-textarea').bind('blur', function(){
          if ($(this).val() == '') {
              $(this).attr('class', 'textOff');
              $(this).val(Drupal.t("What's happening?"));
          }
      });
      $('#edit-textarea').keyup(function() {
        delay(function() {
          total = 140 - parseInt($('#edit-textarea').val().length);
          $('#totalchar').html(total);
        }, 200);
      });
    }
  }

})(jQuery);
