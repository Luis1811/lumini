package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.models.Token;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.util.Objects;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin
public class AuthUserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTutil jwt;

    @PostMapping("/login")
    public ResponseEntity loginUser(@RequestBody UserDto userDto) throws NoSuchPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException, InvalidKeyException, NoSuchProviderException {

        Optional<User> checkedUser = userService.getUserByEmail(userDto.getEmail());
        if(checkedUser.isEmpty()){
            return new ResponseEntity<>("USERNAME INORRECT", HttpStatus.NOT_FOUND);
        }
        User u = checkedUser.get();
        if(!Objects.equals(u.getPassword(), userDto.getPassword())){
            return new ResponseEntity<>("PASSWORD INCORRECT", HttpStatus.NOT_FOUND);
        }
        String t = jwt.create(String.valueOf(u.getId()), u.getEmail()); // generando un
        // token devuelto para ser almacenado en cliente
        return new ResponseEntity(new Token(t),HttpStatus.NOT_FOUND );
    }

    @GetMapping("/logged")
    public boolean isLogged(@RequestHeader(value = "Authorization") String token) {

        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)){
            return true;
        }
        return false;
    }

}