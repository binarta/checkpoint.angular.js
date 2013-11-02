angular.module("checkpoint.accounts", [])
    .config(['$routeProvider', function($routeProvider) {
        $routeProvider
            .when('/changemypassword', {templateUrl:'partials/checkpoint/changemypassword.html', controller: ['$scope', '$http', 'config', ChangeMyPasswordController]})
            .when('/:locale/changemypassword', {templateUrl:'partials/checkpoint/changemypassword.html', controller: ['$scope', '$http', 'config', ChangeMyPasswordController]})
    }]);


function ChangeMyPasswordController($scope, $http, config) {
    var onSuccess = function () {
        $scope.ok = true;
    };

    var onError = function (body, status) {
        var handlers = {
            403: function () {
                $scope.forbidden = true;
            }
        };
        if (handlers[status] == undefined) alert(status + ' - ' + body);
        else handlers[status]();
    };

    var resetStates = function () {
        $scope.ok = false;
        $scope.forbidden = false;
    };

    $scope.currentPassword = '';
    $scope.newPassword = '';
    $scope.submit = function () {
        resetStates();
        $http.post((config.baseUri || '') + 'account/password', {
            currentPassword: $scope.currentPassword,
            newPassword: $scope.newPassword
        }, {withCredentials:true}).success(onSuccess).error(onError);
    };

    resetStates();
}