function App(){
  this.$autofocusInput = $('input[autofocus]');
  this.$informationInputs = $('input[type=text], input[type=email]');
  this.$paneToggles = $('.pane .toggle');
  this.$payForm = $('#payment-form');
  this.$payButton = $('.button.primary');
  this.$paySuccess = $('.success');
  this.$noticeEnabled = $('.notice-enabled');
  this.$noticePayment = $('.notice-payment');

  this.focusClass = "has-focus";
  this.openClass = "open";
  this.showClass = "show";
  this.loadingClass = 'loading';

  this.init();
};

App.prototype.init = function(){
  var self = this;

  this.labelFocus('label');
  this.populateEmail();
  this.selectInputEnd();
  this.paneToggles();
  this.payment();

  window.setTimeout(function(){
    $('.notice-enabled').addClass(self.showClass);
  },400);
};

App.prototype.generateIdentifier = function(size){
  var identifier = "";
  var characters = "bcdfghjklmnpqrstvwxz0123456789";

  for( var i=0; i < size; i++ ) {
    identifier += characters.charAt(Math.floor(Math.random() * characters.length));
  }

  return identifier;
};

App.prototype.populateEmail = function(){
  var input = $('input[type=email]');

  if (!input.length) return;

  var root = 'demo.merchant+';
  var domain = 'test.com';
  var random = this.generateIdentifier(5);
  var address = root + random + '@' + domain;

  input.val(address);
};

App.prototype.payment = function(){
  var self = this;

  this.$payForm.on('submit',function(event){
    event.preventDefault();

    console.log('loading...');
    self.$payButton.addClass(self.loadingClass);
  });
};

App.prototype.clearPaymentLoading = function(){
  this.$payButton.removeClass(this.loadingClass);
};

App.prototype.showPaymentSuccess = function(){
  var self = this;
  var pane = $('.pane');

  this.$paySuccess.addClass(this.showClass);

  window.setTimeout(function(){
    app.closePane(pane);
    app.clearPaymentLoading();
    self.$noticeEnabled.removeClass(self.showClass);

    window.setTimeout(function(){
      self.$noticePayment.addClass(self.showClass);
    }, 600);
  }, 2000);
};

App.prototype.triggerPaymentSubmit = function () {
  return this.$payForm.trigger('submit');
};

App.prototype.labelFocus = function(parent){
  var self = this;

  this.$informationInputs.on('focus', function(){
    $(this).parent(parent).addClass(self.focusClass);
  }).on('blur', function(){
    $(this).parent(parent).removeClass(self.focusClass);
  });
};

App.prototype.selectInputEnd = function(){
  this.$autofocusInput.trigger('focus');
  var initialValue = this.$autofocusInput.val();
  this.$autofocusInput.val('').val(initialValue);
};

App.prototype.paneToggles = function(){
  var self = this;

  this.$paneToggles.each(function(index, element){
    var toggle = $(element);
    var toggleWidth = Math.ceil(toggle.outerWidth()) + 1;

    toggle.data("original-width", toggleWidth).css({
      "width" : toggleWidth
    });
  });

  this.$paneToggles.on('click', function(event){
    event.preventDefault();

    var toggle = $(this);
    var pane = toggle.parent('.pane');
    var open = pane.hasClass(self.openClass);

    if (open) {
      self.closePane(pane);
    } else {
      self.openPane(pane);
    }
  });

  $(document).keyup(function(e) {
    if (e.keyCode == 27) {
      var pane = $('.pane');
      self.closePane(pane);
    };
  });
};

App.prototype.openPane = function(pane){
  var self = this;
  var toggle = pane.find('.toggle');
  var title = pane.find('.title');
  var height = pane.children('section').outerHeight() * -1;
  var tooltip = $('.tooltip');

  tooltip.removeClass('active');

  toggle.css({"width": pane.width()});

  window.setTimeout(function(){
    pane.addClass(self.openClass).css({
      '-webkit-transform' : 'translateY(' + height + 'px)',
      '-moz-transform'    : 'translateY(' + height + 'px)',
      '-ms-transform'     : 'translateY(' + height + 'px)',
      '-o-transform'      : 'translateY(' + height + 'px)',
      'transform'         : 'translateY(' + height + 'px)'
    });
  }, 200);
};

App.prototype.closePane = function(pane){
  var self = this;
  var toggle = pane.find('.toggle');

  pane.removeClass(self.openClass).css({
    '-webkit-transform' : 'translateY(0%)',
    '-moz-transform'    : 'translateY(0%)',
    '-ms-transform'     : 'translateY(0%)',
    '-o-transform'      : 'translateY(0%)',
    'transform'         : 'translateY(0%)'
  });

  window.setTimeout(function(){
    toggle.css({"width": toggle.data("original-width")});
  }, 400);
};

var app = new App();
