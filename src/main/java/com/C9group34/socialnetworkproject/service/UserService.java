package com.C9group34.socialnetworkproject.service;


import com.C9group34.socialnetworkproject.dto.UserDto;
import com.C9group34.socialnetworkproject.exceptions.ExistingResourceException;
import com.C9group34.socialnetworkproject.exceptions.ResourceNotFoundException;
import com.C9group34.socialnetworkproject.models.User;
import com.C9group34.socialnetworkproject.repository.UserRepository;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PublicationService publicationService;
    private final FavoritePublicationService favoritePublicationService;


    public UserService(UserRepository userRepository, PublicationService publicationService,
                       FavoritePublicationService favoritePublicationService) {
        this.userRepository = userRepository;
        this.publicationService = publicationService;
        this.favoritePublicationService = favoritePublicationService;
    }

    public User register(UserDto userDto) {
        User user = mapToEntity(userDto);
        checkForExistingUser(user.getId());
        user = userRepository.save(user);
        return user;

    }

    public List<UserDto> retrieveAll() {
        List<User> users = userRepository.findAll();
        return users.stream()
                .map(user -> mapToDTO(user))
                .collect(Collectors.toList());
    }

    public UserDto retrieveById(Integer userId) {
        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está buscando no existe.");
        }

        return mapToDTO(user.get());
    }


    public UserDto retrieveByIdWithFavoritePublications(Integer userId){
        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            throw new ResourceNotFoundException("El id del usuario que está buscando no existe.");
        }

        return mapToDTOWithFavoritePublications(user);
    }


    public void delete(Integer userId) {
        try {
            userRepository.deleteById(userId);
        } catch (EmptyResultDataAccessException e) {
            throw new ResourceNotFoundException("No se pudo eliminar el usuario porque el id que está ingresando no existe.");
        }
    }

    public void replace(Integer userId, User userDTO) {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        User updatedUser;
        User userToReplace = user.get();
        updatedUser = new User().builder().id(userToReplace.getId())
                .name(userDTO.getName())
                .surname(userDTO.getSurname())
                .email(userDTO.getEmail())
                .phone(userDTO.getPhone())
                .password(userDTO.getPassword())
                .ratings(userDTO.getRatings()).build();


        userRepository.save(updatedUser);
    }

    public void modify(Integer userId, Map<String, Object> fieldsToModify) {
        Optional<User> user = userRepository.findById(userId);
        if (user.isEmpty()) {
            throw new ResourceNotFoundException();
        }
        User userToModify = user.get();
        fieldsToModify.forEach((key, value) -> userToModify.modifyAttributeValue(key, value));
        userRepository.save(userToModify);
    }


    //estos serian para mapear
    private User mapToEntity(UserDto userDto) {
        userDto.setRatings(0.0);
        User user = new User().builder().name(userDto.getName())
                .surname(userDto.getSurname())
                .email(userDto.getEmail())
                .phone(userDto.getPhone())
                .password(userDto.getPassword())
                .ratings(userDto.getRatings()).build();
        return user;
    }


    private UserDto mapToDTO(User user) {

        UserDto userDto = new UserDto(user.getId(), user.getName(), user.getSurname(), user.getEmail(),
                user.getPhone(), user.getPassword(), user.getRatings());

        return userDto;
    }

    private UserDto mapToDTOWithFavoritePublications(Optional<User> user) {

        UserDto userDto = new UserDto(user.get().getId(), user.get().getName(), user.get().getSurname(), user.get().getEmail(),
                user.get().getPhone(), user.get().getPassword(), user.get().getRatings());
        return userDto;
    }

    //metodo para la exception
    private void checkForExistingUser(Integer userId) {
        if (userRepository.existsById(userId)) {
            throw new ExistingResourceException("El usuario que está intentando crear ya existe.");
        }
    }

}
