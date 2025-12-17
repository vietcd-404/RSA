module com.haui.rsa {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;


    opens com.haui.rsa to javafx.fxml;
    exports com.haui.rsa;
}