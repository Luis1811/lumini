package com.C9group34.socialnetworkproject.repository;

import com.C9group34.socialnetworkproject.models.Publication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.JpaRepository;
public interface PublicationRepository extends JpaRepository<Publication, Integer> {
}
