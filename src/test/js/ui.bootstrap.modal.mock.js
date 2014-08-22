angular.module('ui.bootstrap.modal', [])
    .factory('$modal', function (modalSpy) {
        return {
            open: function (args) {
                modalSpy.templateUrl = args.templateUrl;
                modalSpy.backdrop = args.backdrop;
            }
        }
    })
    .factory('modalSpy', function () {
        return {};
    });