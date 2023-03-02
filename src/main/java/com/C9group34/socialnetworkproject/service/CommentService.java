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

    @Transactional
    public Comment register(CommentDto comment) throws ExistingResourceException {
        Comment c = mapToEntity(comment);
        checkForExistingComment(c.getId());
        c = commentRepository.save(c);
        return c;

    }
    @Transactional
    public List<CommentDto> retrieveAll() {
        List<Comment> comments = commentRepository.findAll();
        List commentDtoList = new ArrayList<>();
        comments.forEach(c -> commentDtoList.add(mapToDTO(c)));
        return commentDtoList;
    }
    @Transactional
    public CommentDto retrieveById(Integer id) throws ResourceNotFoundException {
        Optional<Comment> commentOptional = commentRepository.findById(id);
        if(commentOptional.isEmpty()){
            throw  new ResourceNotFoundException("El comentario no ha sido encontrado");
        }

        return mapToDTO(commentOptional.get());
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
    public void replace(Integer id, CommentDto dto) throws ResourceNotFoundException {
        Optional<Comment> commentOptional = commentRepository.findById(id);
        if (commentOptional.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        Comment updatedComment;
        Comment commentToReplace = commentOptional.get();
        new Comment();
        updatedComment = Comment.builder().id(commentToReplace.getId())
                .content(dto.getContent())
                .publication(dto.getPublication())
                .user(dto.getUser())
                .build();
        commentRepository.save(updatedComment);
    }


    private Comment mapToEntity(CommentDto dto) {

        new Comment();
        return Comment.builder()
                .content(dto.getContent())
                .user(dto.getUser())
                .publication(dto.getPublication())
                .build();
    }

    private CommentDto mapToDTO(Comment c) {

        return CommentDto.builder()
                .id(c.getId())
                .content(c.getContent())
                .publication(c.getPublication())
                .user(c.getUser())
                .build();
    }

    private Optional<UserDto> mapToDTOWithFavoritePublications(Optional<User> optionalUser) {
        if(optionalUser.isEmpty()){
            return Optional.empty();
        }
        User user = optionalUser.get();
        return Optional.ofNullable(UserDto.builder().id(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .email(user.getEmail())
                .phone(user.getPhone())
                .password(user.getPassword())
                .ratings(user.getRatings())
                .build());
    }


    private void checkForExistingComment(Integer commentId) throws ExistingResourceException {
        if (commentRepository.existsById(commentId)) {
            throw new ExistingResourceException("El commentario que está intentando crear ya existe.");
        }
    }
}
