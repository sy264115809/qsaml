/**
 * Set focus to the element with the given id.
 *
 * @param id  The id of the element which should receive focus.
 */
function qSAMLFocus(id) {
  element = document.getElementById(id);
  if(element != null) {
    element.focus();
  }
}


/**
 * Show the given DOM element.
 *
 * @param id  The id of the element which should be shown.
 */
function qSAMLShow(id) {
  element = document.getElementById(id);
  if (element == null) {
    return;
  }

  element.style.display = 'block';
}


/**
 * Hide the given DOM element.
 *
 * @param id  The id of the element which should be hidden.
 */
function qSAMLHide(id) {
  element = document.getElementById(id);
  if (element == null) {
    return;
  }

  element.style.display = 'none';
}

$(document).ready(function () {
  jQuery.support.placeholder = false;
  test = document.createElement('input');
  if('placeholder' in test) jQuery.support.placeholder = true;
  if(!$.support.placeholder) {
    $("label").show();
  }

  $( "#link-help" ).click(function() {
    $("#cover").fadeIn("fast");
    $("#dialog-help").fadeIn("fast");
  });
  $( "#link-forgot" ).click(function() {
    $("#cover").fadeIn("fast");
    $("#dialog-forgot").fadeIn("fast");
  });
  $( ".dialog-close" ).click(function() {
    $("#cover").fadeOut("fast");
    $(".dialog-box").fadeOut("fast");
  });
});
