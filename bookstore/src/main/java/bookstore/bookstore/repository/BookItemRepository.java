package bookstore.bookstore.repository;

import bookstore.bookstore.model.BookItemModel;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BookItemRepository extends JpaRepository<BookItemModel, Integer> {
}
