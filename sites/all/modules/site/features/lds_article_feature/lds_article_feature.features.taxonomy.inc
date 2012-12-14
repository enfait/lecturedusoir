<?php
/**
 * @file
 * lds_article_feature.features.taxonomy.inc
 */

/**
 * Implements hook_taxonomy_default_vocabularies().
 */
function lds_article_feature_taxonomy_default_vocabularies() {
  return array(
    'tags' => array(
      'name' => 'Étiquettes',
      'machine_name' => 'tags',
      'description' => 'Utilisez les étiquettes pour regrouper les articles sur des sujets similaires dans des catégories.',
      'hierarchy' => '0',
      'module' => 'taxonomy',
      'weight' => '0',
      'rdf_mapping' => array(
        'rdftype' => array(
          0 => 'skos:ConceptScheme',
        ),
        'name' => array(
          'predicates' => array(
            0 => 'dc:title',
          ),
        ),
        'description' => array(
          'predicates' => array(
            0 => 'rdfs:comment',
          ),
        ),
      ),
    ),
  );
}
