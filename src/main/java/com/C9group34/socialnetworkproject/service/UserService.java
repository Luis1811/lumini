package com.C9group34.socialnetworkproject.service;

import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.Conversation;
import com.C9group34.socialnetworkproject.models.FavoritePublication;
import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private  UserRepository userRepository;

    @Transactional
    public User register(UserDto userDto) throws ExistingResourceException {
        User user = createNewEntity(userDto);
        checkForExistingUser(user.getId());
        user = userRepository.save(user);
        return user;

    }
    @Transactional
    public List<UserDto> retrieveAll() {
        List<User> users = userRepository.findAll();
        List userDtoList = new ArrayList<UserDto>();
        users.forEach(user -> userDtoList.add(mapToDTO(user)));
        return userDtoList;
    }
    @Transactional
    public UserDto retrieveById(Integer userId) throws ResourceNotFoundException {
        Optional<User> userOptional = userRepository.findById(userId);
        if(userOptional.isEmpty()){
            throw  new ResourceNotFoundException("El usuario no ha sido encontrado");
        }

        return mapToDTO(userOptional.get());
    }


    @Transactional
    public void delete(Integer userId) throws ResourceNotFoundException {
        try {
            userRepository.deleteById(userId);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException("No se pudo eliminar el usuario porque el id que está ingresando no existe.");
        }
    }

    @Transactional
    public void replace(Integer userId, UserDto userDTO) throws ResourceNotFoundException {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        User updatedUser;
        User userToReplace = user.get();
        new User();
        updatedUser = User.builder().id(userToReplace.getId())
                .name(userDTO.getName())
                .surname(userDTO.getSurname())
                .email(userDTO.getEmail())
                .phone(userDTO.getPhone())
                .imgProfile(userDTO.getImgProfile())
                .password(userDTO.getPassword())
                .imgProfile(userDTO.getImgProfile())
                .publications(new ArrayList<Publication>())
                .favoritePublications(new ArrayList<FavoritePublication>())
                .conversations(new ArrayList<Conversation>())
                .ratings(userDTO.getRatings()).build();
        userRepository.save(updatedUser);
    }

    @Transactional
    public Optional<User> getUserByEmail(String email) {
        return Optional.ofNullable(userRepository.findByEmail(email));
    }


    private User createNewEntity(UserDto userDto){
        new User();
        return User.builder().name(userDto.getName())
                .surname(userDto.getSurname())
                .email(userDto.getEmail())
                .phone(userDto.getPhone())
                .imgProfile(userDto.getImgProfile())
                .publications(new ArrayList<Publication>())
                .favoritePublications(new ArrayList<FavoritePublication>())
                .conversations(new ArrayList<Conversation>())
                .password(userDto.getPassword())
                .ratings(userDto.getRatings())
                .build();
    }


    private User mapToEntity(UserDto userDto) {

        new User();
        return User.builder().name(userDto.getName())
                .surname(userDto.getSurname())
                .email(userDto.getEmail())
                .phone(userDto.getPhone())
                .imgProfile(userDto.getImgProfile())
                .publications(userDto.getPublications())
                .favoritePublications(userDto.getFavoritePublications())
                .conversations(userDto.getConversations())
                .password(userDto.getPassword())
                .ratings(userDto.getRatings())
                .build();
    }

    private UserDto mapToDTO(User user) {

        return UserDto.builder().id(user.getId())
                .name(user.getName())
                .surname(user.getSurname())
                .email(user.getEmail())
                .phone(user.getPhone())
                .imgProfile(user.getImgProfile())
                .publications(user.getPublications())
                .favoritePublications(user.getFavoritePublications())
                .conversations(user.getConversations())
                .password(user.getPassword())
                .ratings(user.getRatings())
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


    private void checkForExistingUser(Integer userId) throws ExistingResourceException {
        if (userRepository.existsById(userId)) {
            throw new ExistingResourceException("El usuario que está intentando crear ya existe.");
        }
    }
}
