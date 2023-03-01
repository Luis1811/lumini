package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.PublicationDto;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.service.PublicationService;
import com.C9group34.socialnetworkproject.service.UserService;
import com.C9group34.socialnetworkproject.util.JWTutil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Query;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(path = "/users/publications")

@CrossOrigin
public class PublicationController {

    @Autowired
    private PublicationService publicationService;
    @Autowired
    private UserService userService;
    @Autowired
    private JWTutil jwt;

    @PostMapping
    @Operation(
            summary = "Create publication",
            description = "This endpoint is for create a publication of a user"
    )
    public ResponseEntity create(@RequestHeader(value = "Authorization") String token,
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                            value = "{ \"title\": \"string\", \"description\": \"string\", \"img\": \"string\", \"category\": 1 }"
                    )
            )
    ) @RequestBody PublicationDto publicationDTO)

    {
        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)) {
            return new ResponseEntity<>(publicationService.create(publicationDTO, Integer.valueOf(id)), HttpStatus.CREATED);
        }
        return new ResponseEntity<>("Accion no realizada", HttpStatus.UNAUTHORIZED);

    }

    @GetMapping("/all")
    @Query(value = "select publications.id, publications.title, publications.description, publications.url_imgs, publications.ratings, publications.category_id, publications.user_id, users.img_profile FROM publications INNER JOIN users ON publications.user_id = users.id ORDER BY publications.id;", nativeQuery = true)
    public ResponseEntity getAll(){
        return new ResponseEntity(publicationService.getAll(), HttpStatus.OK);
    }

    @GetMapping
    public ResponseEntity retrieve(@RequestHeader(value = "Authorization") String token){
        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)){
            try {
                return new ResponseEntity(publicationService.retrieveAll(Integer.valueOf(id)), HttpStatus.OK);
            } catch (ResourceNotFoundException e) {
                System.out.println(e.getMessage());
                return new ResponseEntity(HttpStatus.NOT_FOUND);
            }
        }
        return new ResponseEntity<>("Accion no realizada", HttpStatus.UNAUTHORIZED);
    }

    @GetMapping("/{publicationId}")
    public ResponseEntity retrieveById(@RequestHeader(value = "Authorization") String token,
                                       @PathVariable Integer publicationId){
        PublicationDto publicationDto = null;
        if (jwt.verifyToken(token)){
            try {
                publicationDto = publicationService.retrieveById(publicationId);
                return new ResponseEntity(publicationDto, HttpStatus.OK);
            } catch (ResourceNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        return new ResponseEntity<>("Accion no realizada", HttpStatus.UNAUTHORIZED);
    }


    @DeleteMapping("/{publicationId}")
    public ResponseEntity delete(@RequestHeader(value = "Authorization") String token,
                                 @PathVariable Integer publicationId){
        if (jwt.verifyToken(token)){
            try {
                publicationService.delete(publicationId);
                return new ResponseEntity(HttpStatus.OK);
            } catch (ResourceNotFoundException e) {
                throw new RuntimeException(e);
            }
        }
        return new ResponseEntity<>("Accion no realizada", HttpStatus.UNAUTHORIZED);
    }

    @PutMapping("/{publicationId}")
    public ResponseEntity replace(@RequestHeader(value = "Authorization") String token,
                                  @PathVariable Integer publicationId,
                                  @RequestBody PublicationDto publicationDTO) {
        String id = jwt.getKey(token);
        if (jwt.verifyToken(token)){
            try {
                publicationService.replace(Integer.valueOf(id), publicationId, publicationDTO);

            } catch (ResourceNotFoundException e) {
                System.out.println(e.getMessage());
                return new ResponseEntity(HttpStatus.BAD_REQUEST);
            }
            return new ResponseEntity(HttpStatus.OK);
        }
        return new ResponseEntity<>("Accion no realizada", HttpStatus.UNAUTHORIZED);

    }

}