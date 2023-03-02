package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.CommentDto;
import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.*;
import com.C9group34.socialnetworkproject.repository.CommentRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class CommentService {

    @Autowired
    private CommentRepository commentRepository;
    @Autowired
    private PublicationService publicationService;
    @Autowired
    private UserService userService;

    @Transactional
    public Comment register(CommentDto comment, Integer publicationId, Integer userId) throws ExistingResourceException, ResourceNotFoundException {
        Comment c = mapToEntity(comment, publicationId, userId);
        checkForExistingComment(c.getId());
        c = commentRepository.save(c);
        return c;

    }
    @Transactional
    public List<CommentDto> retrieveAll(Integer publicationId) {
         List<Comment> comments = commentRepository.retrieveAllCommentsOfAPublication(publicationId);
         List commentDtoList = new ArrayList<>();
         comments.forEach(c -> commentDtoList.add(mapToDTO(c)));
        return commentDtoList;
    }


    @Transactional
    public void delete(Integer id) throws ResourceNotFoundException {
        try {
            commentRepository.deleteById(id);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException("No se pudo eliminar el commentario porque el id ingresando no existe.");
        }
    }

    @Transactional
    public void replace(Integer id, CommentDto dto, Integer userId, Integer publicationId) throws ResourceNotFoundException {
        Optional<Comment> commentOptional = commentRepository.findById(id);
        if (commentOptional.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        Optional<User> userOptional = userService.retrieveWithoutMapToDTO(userId);
        Optional<Publication> publicationOptional = publicationService.retrieveWithoutMapToDTO(publicationId);
        if(userOptional.isEmpty() || publicationOptional.isEmpty()){
            System.out.println("ERROR");
        }
        Publication publication = publicationOptional.get();
        User user = userOptional.get();
        Comment updatedComment;
        Comment commentToReplace = commentOptional.get();
        new Comment();
        updatedComment = Comment.builder().id(commentToReplace.getId())
                .content(dto.getContent())
                .publication(publication)
                .user(user)
                .build();
        commentRepository.save(updatedComment);
    }



    private Comment mapToEntity(CommentDto dto, Integer publicationId, Integer userId) throws ResourceNotFoundException {

        Optional<Publication> p = publicationService.retrieveWithoutMapToDTO(publicationId);
        Optional<User> u = userService.retrieveWithoutMapToDTO(userId);
        if (p.isEmpty() && u.isEmpty()){
            throw new ResourceNotFoundException("usuario o publicacon no encontrados");
        }
        new Comment();
        return Comment.builder()
                .content(dto.getContent())
                .user(u.get())
                .publication(p.get())
                .build();
    }

    private CommentDto mapToDTO(Comment c) {

        User user = c.getUser();
        UserDto userDto = new UserDto().builder()
                .name(user.getName())
                .surname(user.getSurname())
                .email(user.getEmail())
                .ratings(user.getRatings())
                .imgProfile(user.getImgProfile())
                .build();
        return CommentDto.builder()
                .id(c.getId())
                .content(c.getContent())
                .user(userDto)
                .build();
    }



    private void checkForExistingComment(Integer commentId) throws ExistingResourceException {
        if (commentRepository.existsById(commentId)) {
            throw new ExistingResourceException("El commentario que está intentando crear ya existe.");
        }
    }
}
