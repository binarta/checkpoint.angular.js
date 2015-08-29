angular.module("checkpoint.templates", []).run(["$templateCache", function($templateCache) {$templateCache.put("bin-checkpoint-change-password-form.html","<form class=\"bin-checkpoint-form\" ng-submit=\"checkpoint.submit()\"><div class=\"form-group\"><i class=\"fa fa-eye-slash addon\"></i> <label class=\"hidden\" for=\"binCurrentPassword\" i18n=\"\" code=\"checkpoint.current.password.label\" var=\"currentPasswordLabel\" read-only=\"\">{{var}}</label> <input type=\"password\" id=\"binCurrentPassword\" class=\"form-control\" placeholder=\"{{currentPasswordLabel}}\" ng-model=\"checkpoint.currentPassword\" required=\"\" autofocus=\"\"></div><div class=\"form-group\"><i class=\"fa fa-eye-slash addon\"></i> <label class=\"hidden\" for=\"binNewPassword\" i18n=\"\" code=\"checkpoint.new.password.label\" var=\"newPasswordLabel\" read-only=\"\">{{var}}</label> <input type=\"password\" id=\"binNewPassword\" class=\"form-control\" placeholder=\"{{newPasswordLabel}}\" ng-model=\"checkpoint.newPassword\" required=\"\"></div><p class=\"text-danger\" ng-if=\"checkpoint.forbidden\"><span i18n=\"\" code=\"checkpoint.current.password.mismatch\" read-only=\"\">{{var}}</span></p><p class=\"text-success\" ng-show=\"checkpoint.ok\"><span i18n=\"\" code=\"checkpoint.change.password.success\" read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\" i18n=\"\" code=\"checkpoint.change.password.submit\" read-only=\"\">{{var}}</button></form>");
$templateCache.put("bin-checkpoint-password-token-sent-form.html","<p class=\"text-success text-center\"><span i18n=\"\" code=\"checkpoint.reset.password.token.sent\" read-only=\"\">{{var}}</span></p>");
$templateCache.put("bin-checkpoint-recover-password-form.html","<form class=\"bin-checkpoint-form\" ng-submit=\"checkpoint.submit()\"><div class=\"form-group\"><i class=\"fa fa-envelope-o addon\"></i> <label class=\"hidden\" for=\"binEmail\" i18n=\"\" code=\"checkpoint.email.label\" var=\"emailLabel\" read-only=\"\">{{var}}</label> <input type=\"email\" id=\"binEmail\" class=\"form-control\" placeholder=\"{{emailLabel}}\" ng-model=\"checkpoint.email\" required=\"\" autofocus=\"\"></div><p class=\"text-danger\" ng-if=\"checkpoint.violation\"><span i18n=\"\" code=\"checkpoint.{{checkpoint.violation}}\" default=\"{{checkpoint.violation}}\" read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\" i18n=\"\" code=\"checkpoint.recover.password.submit\" read-only=\"\">{{var}}</button> <a href=\"#!{{localePrefix}}/signin\" i18n=\"\" code=\"checkpoint.login.link\" read-only=\"\">{{var}}</a></form>");
$templateCache.put("bin-checkpoint-registration-form.html","<form class=\"bin-checkpoint-form\" ng-submit=\"checkpoint.register()\" name=\"registrationForm\"><div class=\"form-group\" ng-class=\"{\'has-error\': violations.email}\"><i class=\"fa fa-envelope-o addon\"></i> <label class=\"hidden\" for=\"email\" i18n=\"\" code=\"checkpoint.email.label\" var=\"emailLabel\" read-only=\"\">{{::var}}</label> <input type=\"email\" id=\"email\" name=\"email\" class=\"form-control\" placeholder=\"{{::emailLabel}}\" ng-model=\"checkpoint.email\" required=\"\" autofocus=\"\"></div><div class=\"form-group\" ng-class=\"{\'has-error\': violations.password}\"><i class=\"fa fa-eye-slash addon\"></i> <label class=\"hidden\" for=\"password\" i18n=\"\" code=\"checkpoint.password.label\" var=\"passwordLabel\" read-only=\"\">{{::var}}</label> <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"{{::passwordLabel}}\" ng-model=\"checkpoint.password\" required=\"\" autofocus=\"\"></div><hr><div class=\"checkbox\"><label><input type=\"checkbox\" name=\"company\" ng-model=\"checkpoint.company\" ng-true-value=\"\'yes\'\" ng-false-value=\"\'no\'\"> <span i18n=\"\" code=\"checkpoint.i.represent.a.company\" read-only=\"\">{{::var}}</span></label></div><div class=\"form-group\" ng-class=\"{\'has-error\': violations.vat}\" ng-if=\"checkpoint.company == \'yes\'\"><i class=\"fa fa-building-o addon\"></i> <label class=\"hidden\" for=\"vat\" i18n=\"\" code=\"checkpoint.vat.label\" var=\"vatLabel\" read-only=\"\">{{::var}}</label> <input type=\"text\" id=\"vat\" name=\"vat\" class=\"form-control\" placeholder=\"{{::vatLabel}}\" ng-model=\"checkpoint.vat\" required=\"\" autofocus=\"\"> <small class=\"help-block\" i18n=\"\" code=\"checkpoint.vat.help\" read-only=\"\"><i class=\"fa fa-question-circle fa-fw\"></i> {{::var}}</small></div><hr><div class=\"form-group\"><div class=\"captcha\" vc-recaptcha=\"\" ng-model=\"checkpoint.captcha\" key=\"6LfF8usSAAAAAKeLHU0D3Xjlqv6SqVwymcqB-SHg\" theme=\"white\"></div></div><div class=\"form-group\"><button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\" i18n=\"\" code=\"checkpoint.register.submit\" read-only=\"\" ng-disabled=\"registrationForm.$invalid\">{{::var}}</button> <small class=\"help-block\" i18n=\"\" code=\"checkpoint.register.terms.agreement\" read-only=\"\"><i class=\"fa fa-info-circle fa-fw\"></i> {{::var}}</small></div></form>");
$templateCache.put("bin-checkpoint-reset-password-form.html","<form class=\"bin-checkpoint-form\" ng-submit=\"checkpoint.submit()\"><div class=\"form-group\"><i class=\"fa fa-eye-slash addon\"></i> <label class=\"hidden\" for=\"binPassword\" i18n=\"\" code=\"checkpoint.new.password.label\" var=\"newPasswordLabel\" read-only=\"\">{{var}}</label> <input type=\"password\" id=\"binPassword\" class=\"form-control\" placeholder=\"{{newPasswordLabel}}\" ng-model=\"checkpoint.password\" required=\"\" autofocus=\"\"></div><p class=\"text-danger\" ng-if=\"checkpoint.violation\"><span i18n=\"\" code=\"checkpoint.{{checkpoint.violation}}\" default=\"{{checkpoint.violation}}\" read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\" i18n=\"\" code=\"checkpoint.reset.password.submit\" read-only=\"\">{{var}}</button></form>");
$templateCache.put("bin-checkpoint-signin-form-buttons.html","<button type=\"submit\" class=\"btn btn-lg btn-primary btn-block\" i18n=\"\" code=\"checkpoint.login.submit\" read-only=\"\">{{var}}</button>");
$templateCache.put("bin-checkpoint-signin-form-fields.html","<div class=\"form-group\"><i class=\"fa fa-user addon\"></i> <label class=\"hidden\" for=\"binUsername\" i18n=\"\" code=\"checkpoint.username.email.label\" var=\"usernameLabel\" read-only=\"\">{{::var}}</label> <input type=\"text\" id=\"binUsername\" class=\"form-control\" placeholder=\"{{::usernameLabel}}\" ng-model=\"checkpoint.username\" required=\"\" autofocus=\"\"></div><div class=\"form-group\"><i class=\"fa fa-eye-slash addon\"></i> <label class=\"hidden\" for=\"binPassword\" i18n=\"\" code=\"checkpoint.password.label\" var=\"passwordLabel\" read-only=\"\">{{::var}}</label> <input type=\"password\" id=\"binPassword\" class=\"form-control\" placeholder=\"{{::passwordLabel}}\" ng-model=\"checkpoint.password\" required=\"\"></div><p class=\"text-danger\" ng-if=\"checkpoint.violation\"><span i18n=\"\" code=\"checkpoint.{{checkpoint.violation}}\" default=\"{{checkpoint.violation}}\" read-only=\"\">{{var}}</span></p>");
$templateCache.put("bin-checkpoint-signin-form-links.html","<div class=\"links\"><div><a ng-href=\"#!{{::localePrefix}}/password/recover\" i18n=\"\" code=\"checkpoint.recover.password.link\" read-only=\"\">{{::var}}</a></div></div>");
$templateCache.put("bin-checkpoint-signin-form-shop-links.html","<div><a href=\"#!{{localePrefix}}/register\" i18n=\"\" code=\"checkpoint.create.account\" read-only=\"\">{{var}}</a></div>");
$templateCache.put("bin-checkpoint-signin-form.html","<form class=\"bin-checkpoint-form\" ng-submit=\"checkpoint.submit()\" ng-controller=\"SigninController\"><ng-include src=\"\'bin-checkpoint-signin-form-fields.html\'\"></ng-include><ng-include src=\"\'bin-checkpoint-signin-form-buttons.html\'\"></ng-include><ng-include src=\"\'bin-checkpoint-signin-form-links.html\'\"></ng-include></form>");
$templateCache.put("bin-checkpoint-signin-shop-form.html","<form class=\"bin-checkpoint-form\" ng-submit=\"checkpoint.submit()\"><ng-include src=\"\'bin-checkpoint-signin-form-fields.html\'\"></ng-include><ng-include src=\"\'bin-checkpoint-signin-form-buttons.html\'\"></ng-include><ng-include src=\"\'bin-checkpoint-signin-form-links.html\'\"></ng-include><ng-include src=\"\'bin-checkpoint-signin-form-shop-links.html\'\"></ng-include></form>");
$templateCache.put("bin-checkpoint-welcome-message.html","<div class=\"panel panel-default\"><div class=\"panel-heading\"><h3 class=\"panel-title\" i18n=\"\" code=\"checkpoint.welcome.message.title\" read-only=\"\">{{var}}</h3></div><div class=\"panel-body\" i18n=\"\" code=\"checkpoint.welcome.message.body\" read-only=\"\">{{var}}</div></div>");}]);