package com.C9group34.socialnetworkproject.controllers;

import com.C9group34.socialnetworkproject.dto.PublicationDto;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.service.PublicationService;
import com.C9group34.socialnetworkproject.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(path = "/users/{userId}/publications")

public class PublicationController {

    @Autowired
    private PublicationService publicationService;
    @Autowired
    private  UserService userService;

    @PostMapping
    public ResponseEntity create(@PathVariable Integer userId,
                                 @RequestBody PublicationDto publicationDTO) {

        publicationService.create(publicationDTO , userId);
        return new ResponseEntity<>(publicationDTO.getId(), HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity retrieve(@PathVariable Integer userId){

        try {
            return new ResponseEntity(publicationService.retrieveAll(userId), HttpStatus.OK);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/{publicationId}")
    public ResponseEntity retrieveById(@PathVariable Integer publicationId){

        PublicationDto publicationDto = null;
        try {
            publicationDto = publicationService.retrieveById(publicationId);
        } catch (ResourceNotFoundException e) {
            throw new RuntimeException(e);
        }

        return new ResponseEntity(publicationDto, HttpStatus.OK);

    }


    @DeleteMapping("/{publicationId}")
    public ResponseEntity delete(@PathVariable Integer publicationId){
        try {
            publicationService.delete(publicationId);
        } catch (ResourceNotFoundException e) {
            throw new RuntimeException(e);
        }

        return new ResponseEntity(HttpStatus.OK);
    }

    @PutMapping("/{publicationId}")
    public ResponseEntity replace(@PathVariable Integer userId,
                                  @PathVariable Integer publicationId,
                                  @RequestBody PublicationDto publicationDTO) {
        try {
            publicationService.replace(userId, publicationId, publicationDTO);
        } catch (ResourceNotFoundException e) {
            System.out.println(e.getMessage());
            return new ResponseEntity(HttpStatus.BAD_REQUEST);
        }

        return new ResponseEntity(HttpStatus.OK);
    }

}