package bookstore.bookstore.controller;

import bookstore.bookstore.model.BookModel;
import bookstore.bookstore.service.BookService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/book")
public class BookController {

    @Autowired
    private BookService bookService;

    @GetMapping
    @CrossOrigin
    public ResponseEntity<?> findAll(){
        return ResponseEntity.ok(bookService.findAll());
    }

    @PostMapping
    public ResponseEntity<?> create(@ModelAttribute BookModel bookModel){
        BookModel bm=bookService.save(bookModel);
        if(bm==null) return (ResponseEntity<?>) ResponseEntity.badRequest();
        return ResponseEntity.ok(bm);
    }

    @PutMapping
    public ResponseEntity<?> update(@ModelAttribute BookModel bookModel){
        BookModel bm=bookService.save(bookModel);
        if(bm==null) return (ResponseEntity<?>) ResponseEntity.badRequest();
        return ResponseEntity.ok(bm);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable String id){
        try{
            int ID=Integer.parseInt(id);
            bookService.delete(ID);
            return (ResponseEntity<?>) ResponseEntity.ok();
        }catch (Exception exception){
            return (ResponseEntity<?>) ResponseEntity.badRequest();
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> findById(@PathVariable String id){
        try{
            int ID=Integer.parseInt(id);
            return (ResponseEntity<?>) ResponseEntity.ok(bookService.findById(ID));
        }catch (Exception exception){
            return (ResponseEntity<?>) ResponseEntity.badRequest();
        }
    }

}
