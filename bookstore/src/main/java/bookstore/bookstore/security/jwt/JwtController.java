package bookstore.bookstore.security.jwt;


import bookstore.bookstore.model.User;
import bookstore.bookstore.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/login")
@CrossOrigin(origins = "*")
public class JwtController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping
    public ResponseEntity<?> jwtPost(@ModelAttribute JwtRequest jwtRequest){
        System.out.println("Hello");
        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    jwtRequest.getUsername(), jwtRequest.getPassword()));
        }catch (Exception exception){
            return ResponseEntity.badRequest().body("Error");
        }
        User user= (User) userService.loadUserByUsername(jwtRequest.getUsername());
        String accessToken=jwtUtil.generateToken(user);
        return ResponseEntity.ok(accessToken);
    }

    @GetMapping
    public ResponseEntity<?> jwtGet(){
        return ResponseEntity.ok("Login");
    }

}
