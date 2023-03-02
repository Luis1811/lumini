package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Comment;
import com.C9group34.socialnetworkproject.models.FavoritePublication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface FavoritePublicationRepository extends JpaRepository<FavoritePublication, Integer> {

    @Query(
            value = "SELECT * FROM FAVORITE_PUBLICATIONS f WHERE f.user_id = :userId",
            nativeQuery = true)
    List<FavoritePublication> retrieveAllFavoritesPublicationasOfAUser(Integer userId);
}
