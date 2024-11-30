package com.example.signup.repository;



import com.example.signup.modal.Movie;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface MovieRepository extends JpaRepository<Movie, Long> {

    // Method to search movies by name or description (case-insensitive)
    Page<Movie> findByNameContainingIgnoreCaseOrDescriptionContainingIgnoreCase(
            String name, String description, Pageable pageable);

    // Change this method to specify which fields you want to search
    @Query("SELECT m FROM Movie m WHERE m.name LIKE %:keyword% OR m.description LIKE %:keyword%")
    Page<Movie> searchMovies(@Param("keyword") String keyword, Pageable pageable);

    List<Movie> findByIsRecommendedTrue();
}
