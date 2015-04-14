angular.module("checkpoint.templates", []).run(["$templateCache", function($templateCache) {$templateCache.put("bin-checkpoint-change-password.html","<div class=bin-checkpoint-container ng-controller=ChangeMyPasswordController><div class=well><legend class=text-center i18n=\"\" code=checkpoint.change.password.title read-only=\"\">{{var}}</legend><img class=bin-checkpoint-profile-img src=//cdn.binarta.com/image/logo/binarta-sign.png srcset=\"//cdn.binarta.com/image/logo/binarta-sign.png 1x, //cdn.binarta.com/image/logo/binarta-sign@2x.png 2x\"><form ng-submit=submit()><input type=password class=form-control i18n=\"\" code=checkpoint.current.password.label read-only=\"\" placeholder={{var}} ng-model=$parent.currentPassword required autofocus> <input type=password class=form-control i18n=\"\" code=checkpoint.new.password.label read-only=\"\" placeholder={{var}} ng-model=$parent.newPassword required><p class=text-danger ng-if=forbidden><span i18n=\"\" code=checkpoint.current.password.mismatch read-only=\"\">{{var}}</span></p><p class=text-success ng-show=ok><span i18n=\"\" code=checkpoint.change.password.success read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=submit i18n=\"\" code=checkpoint.change.password.submit read-only=\"\">{{var}}</button></form></div></div>");
$templateCache.put("bin-checkpoint-password-token-sent.html","<div class=bin-checkpoint-container><div class=well><img class=bin-checkpoint-profile-img src=//cdn.binarta.com/image/checkpoint/message-sent.png srcset=\"//cdn.binarta.com/image/checkpoint/message-sent.png 1x, //cdn.binarta.com/image/checkpoint/message-sent@2x.png 2x\"><p class=\"text-success text-center\"><span i18n=\"\" code=checkpoint.reset.password.token.sent read-only=\"\">{{var}}</span></p></div></div>");
$templateCache.put("bin-checkpoint-recover-password.html","<div class=bin-checkpoint-container ng-controller=RecoverPasswordController><div class=well><legend class=text-center i18n=\"\" code=checkpoint.recover.password.title read-only=\"\">{{var}}</legend><img class=bin-checkpoint-profile-img src=//cdn.binarta.com/image/checkpoint/locked.png srcset=\"//cdn.binarta.com/image/checkpoint/locked.png 1x, //cdn.binarta.com/image/checkpoint/locked@2x.png 2x\"><form ng-submit=submit()><input type=email class=form-control i18n=\"\" code=checkpoint.email.label read-only=\"\" placeholder={{var}} ng-model=$parent.email required autofocus><p class=text-danger ng-if=violation><span i18n=\"\" code=checkpoint.{{violation}} default={{violation}} read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=submit i18n=\"\" code=checkpoint.recover.password.submit read-only=\"\">{{var}}</button></form><a href=#!/signin i18n=\"\" code=checkpoint.login.link read-only=\"\">{{var}}</a></div><a href=https://binarta.com/#!/template-selection i18n=\"\" code=checkpoint.create.account read-only=\"\">{{var}}</a></div>");
$templateCache.put("bin-checkpoint-reset-password.html","<div class=bin-checkpoint-container ng-controller=ResetPasswordController><div class=well><legend class=text-center i18n=\"\" code=checkpoint.reset.password.title read-only=\"\">{{var}}</legend><img class=bin-checkpoint-profile-img src=//cdn.binarta.com/image/logo/binarta-sign.png srcset=\"//cdn.binarta.com/image/logo/binarta-sign.png 1x, //cdn.binarta.com/image/logo/binarta-sign@2x.png 2x\"><form ng-submit=submit()><input type=password class=form-control i18n=\"\" code=checkpoint.new.password.label read-only=\"\" placeholder={{var}} ng-model=$parent.password required autofocus><p class=text-danger ng-if=violation><span i18n=\"\" code=checkpoint.{{violation}} default={{violation}} read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=submit i18n=\"\" code=checkpoint.reset.password.submit read-only=\"\">{{var}}</button></form></div></div>");
$templateCache.put("bin-checkpoint-signin.html","<div class=bin-checkpoint-container ng-controller=SigninController><div class=well><img class=bin-checkpoint-profile-img src=//cdn.binarta.com/image/logo/binarta-sign.png srcset=\"//cdn.binarta.com/image/logo/binarta-sign.png 1x, //cdn.binarta.com/image/logo/binarta-sign@2x.png 2x\"><form ng-submit=submit()><input type=text class=form-control i18n=\"\" code=checkpoint.username.email.label read-only=\"\" placeholder={{var}} ng-model=$parent.username required autofocus> <input type=password class=form-control i18n=\"\" code=checkpoint.password.label read-only=\"\" placeholder={{var}} ng-model=$parent.password required><p class=text-danger ng-if=violation><span i18n=\"\" code=checkpoint.{{violation}} default={{violation}} read-only=\"\">{{var}}</span></p><button class=\"btn btn-lg btn-primary btn-block\" type=submit i18n=\"\" code=checkpoint.login.submit read-only=\"\">{{var}}</button></form><a href=#!/password/recover i18n=\"\" code=checkpoint.recover.password.link read-only=\"\">{{var}}</a></div><a href=https://binarta.com/#!/template-selection i18n=\"\" code=checkpoint.create.account read-only=\"\">{{var}}</a></div>");}]);