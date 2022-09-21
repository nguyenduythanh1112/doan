package bookstore.bookstore.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table
@Data
@NoArgsConstructor
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id")
public class BookModel {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String title;
    private String summary;
    private int numberOfPage;
    private String language;
    private String image;
    private String file;
    private String description;
    private float importedPrice;
    private int importedQuantity;
    private int exportedQuantity;
    private String publisher;
    private String author;
    private String category;

    @OneToOne(mappedBy = "bookModel")
    private BookItemModel bookItemModel;
}
