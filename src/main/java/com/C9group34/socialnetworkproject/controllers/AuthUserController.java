package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.models.Encrypt;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
@CrossOrigin
public class AuthUserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JWTutil jwt;

    @PostMapping("/login")
    @Operation(
            summary = "Login user",
            description = "This endpoint is for to have login to user"

    )
    public ResponseEntity loginUser(@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{ \"email\" : \"luis@example.com\", \"password\" : \"123456789\" }"
                    )
            )
    ) @RequestBody UserDto userDto) throws NoSuchAlgorithmException, InvalidKeySpecException {

        Optional<User> checkedUser = userService.getUserByEmail(userDto.getEmail());
        if(checkedUser.isEmpty()){
            return new ResponseEntity<>("USERNAME INCORRECT", HttpStatus.UNAUTHORIZED);

        }
        User u = checkedUser.get();
        if(Encrypt.validatePassword(userDto.getPassword(), u.getPassword())){
            String t = jwt.create(String.valueOf(u.getId()), u.getEmail()); // generando un
            // token devuelto para ser almacenado en cliente
            return new ResponseEntity(t,HttpStatus.OK );

        }
        return new ResponseEntity<>("PASSWORD INCORRECT", HttpStatus.NOT_FOUND);

    }

    @GetMapping("/logged")
    @Operation(
            summary = "Logged verify",
            description = "This endpoint return TRUE if the user is logged",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "logged")
            }
    )
    public Boolean isLogged(@RequestHeader(value = "Authorization") String token) {

        if (jwt.verifyToken(token)){
            return true;
        }
        return false;
    }

}