package pl.pancerro.jwtapi;


import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/books")
public class BookApi {

    private List<String> bookList;


    public BookApi() {
        this.bookList = new ArrayList<>();
        bookList.add("Spring Boot 2");
        bookList.add("Spring in Action 5");
    }

    @GetMapping
    public List<String> getBookList()  {
        return bookList;
    }

    @PostMapping
    public void setBookList(@RequestBody String book) {
        this.bookList.add(book);
    }
}
