package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/users")
@CrossOrigin(origins = "{host}")
public class UserController {
    /*public ResponseEntity<User> getUser(){
        return null;
    }*/

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/new")
    @Operation(
            summary = "Create new use",
            responses = {
                    @ApiResponse(responseCode = "201",ref = "created"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity register (@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"Luis\", \"surname\" : \"Uzcategui\", \"email\" : \"luis@example.com\", \"password\" : \"123456789\", \"phone\" : \"+593979010717\" }"
                    )
            )
    ) @RequestBody UserDto u){

        User user = userService.register(u);

        return new ResponseEntity(user, HttpStatus.CREATED);

    }

    @GetMapping("/all")
    @Operation(
            summary = "Get all users",
            responses = {
                    @ApiResponse(responseCode = "200",ref = "getAll"),
                    @ApiResponse(responseCode = "400",ref = "badRequest")
            }
    )
    public ResponseEntity retrieve(){

        return new ResponseEntity(userService.retrieveAll(), HttpStatus.OK);
    }

    @GetMapping("/{userId}")
    public ResponseEntity retrieveByIdWithFavoritePublications(@PathVariable Integer userId){

        UserDto userDTO = userService.retrieveByIdWithFavoritePublications(userId);

        return new ResponseEntity(userDTO, HttpStatus.OK);

    }
    @DeleteMapping("/{userId}")
    public ResponseEntity delete(@PathVariable Integer userId) {
        userService.delete(userId);

        return new ResponseEntity(HttpStatus.OK);
    }

    @PutMapping("/{userId}")
    public ResponseEntity replace(@PathVariable Integer userId,@io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{\"name\" : \"String\", \"surname\" : \"String\", \"email\" : \"String\", \"password\" : \"String\", \"phone\" : \"String\", \"ratings\" : 0.0 }"
                    )
            )
    ) @RequestBody User user) {

        userService.replace(userId, user);

        return new ResponseEntity(HttpStatus.OK);
    }

    @PatchMapping("/{userId}")
    public ResponseEntity modify(@PathVariable Integer userId,
                                 @RequestBody Map<String, Object> fieldsToModify) {
        userService.modify(userId, fieldsToModify);

        return new ResponseEntity(HttpStatus.OK);
    }
    
}
