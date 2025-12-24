module com.haui.rsa {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.graphics;
    requires org.apache.poi.poi;
    requires org.apache.poi.ooxml;
    requires org.apache.pdfbox;


    opens com.haui.rsa to javafx.fxml;
    exports com.haui.rsa;
}